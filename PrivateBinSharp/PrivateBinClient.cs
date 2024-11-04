﻿using PrivateBinSharp.Crypto.crypto.digests;
using PrivateBinSharp.Crypto.crypto.engines;
using PrivateBinSharp.Crypto.crypto.generators;
using PrivateBinSharp.Crypto.crypto.modes;
using PrivateBinSharp.Crypto.crypto.parameters;
using PrivateBinSharp.Crypto.security;
using System.Reflection;
using System.Text;

namespace PrivateBinSharp;

/// <summary>
/// Interact with a PrivateBin service to automatically create encrypted data with optional password.
/// </summary>
public class PrivateBinClient
{
	/// <summary>
	/// Create a new PrivateBin http client to use.
	/// </summary>
	/// <param name="hostUrl"></param>
	/// <exception cref="ArgumentException"></exception>
	public PrivateBinClient(string hostUrl)
	{
		if (string.IsNullOrEmpty(hostUrl))
			throw new ArgumentException("Host url can't be empty.");

		HostURL = hostUrl;
		if (!HostURL.EndsWith('/'))
			HostURL += '/';

		Http = new HttpClient();
		if (!Uri.TryCreate(HostURL, UriKind.Absolute, out Uri? uri))
			throw new ArgumentException("Host url is invalid.");

		Http.BaseAddress = uri;
		Http.DefaultRequestHeaders.Add("X-Requested-With", "JSONHttpRequest");
	}

	/// <summary>
	/// The PrivateBin http url to communicate with.
	/// </summary>
	public string HostURL { get; internal set; }

	private bool FirstTimeCheck;

	private readonly HttpClient Http;

	/// <summary>
	/// Version of the current PrivateBinSharp lib installed.
	/// </summary>
	public static string Version => Assembly.GetExecutingAssembly().GetName().Version!.ToString(3);

    /// <summary>
    /// Create a paste that will be encrypted 
    /// </summary>
    /// <param name="text"></param>
    /// <param name="password"></param>
    /// <param name="expire"></param>
    /// <param name="openDiscussion"></param>
    /// <param name="burnAfterReading"></param>
    /// <param name="format"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="Exception"></exception>
    public async Task<Paste> CreatePaste(string text, 
		string password, 
		string expire = "5min", 
		bool openDiscussion = false, 
		bool burnAfterReading = false,
        string format = "plaintext")
	{
		if (string.IsNullOrEmpty(text))
			throw new ArgumentException("Paste text can't be empty.");

		if (FirstTimeCheck)
		{
			HttpResponseMessage? TestRes = null;
			try
			{
				TestRes = await Http.GetAsync(HostURL);
				TestRes.EnsureSuccessStatusCode();
				FirstTimeCheck = false;
			}
			catch
			{
				return new Paste
				{
					IsSuccess = false,
					Response = TestRes
				};
			}
		}
		Tuple<PasteJson, byte[]> Json;
		try
		{
            Json = GeneratePasteData(text, password, expire, openDiscussion, burnAfterReading, format);
		}
		catch (Exception ex)
		{
			throw new Exception("Failed to generate encrypted data, " + ex.Message);
		}

        string body = Newtonsoft.Json.JsonConvert.SerializeObject(Json.Item1);
		HttpRequestMessage Req = new HttpRequestMessage(HttpMethod.Post, HostURL)
		{
			Content = new StringContent(body, Encoding.UTF8)
		};
		Req.Headers.Add("X-Requested-With", "JSONHttpRequest");
		HttpResponseMessage? Res = null;
		try
		{
			Res = await Http.SendAsync(Req);
		}
		catch
		{
			return new Paste
			{
				IsSuccess = false,
				Response = Res
			};
		}

		PasteResponse? ResponseJson;
		try
		{

			string response = await Res.Content.ReadAsStringAsync();
			ResponseJson = Newtonsoft.Json.JsonConvert.DeserializeObject<PasteResponse>(response);
			if (ResponseJson == null)
				return new Paste
				{
					IsSuccess = false,
					Response = new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError) { ReasonPhrase = "Failed to parse json request content to send." }
				};
		}
		catch
		{
			return new Paste
			{
				IsSuccess = false,
				Response = Res
			};
		}
		return new Paste
		{
			IsSuccess = true,
			Response = Res,
			Id = ResponseJson.id,
			Secret = Base58.EncodePlain(Json.Item2),
			DeleteToken = ResponseJson.deletetoken,
			HostURL = HostURL
		};
	}

	private static Tuple<PasteJson, byte[]> GeneratePasteData(string text, 
		string password, 
		string expire, 
		bool openDiscussion, 
		bool burnAfterReading,
		string format)
	{
		SecureRandom rng = new();

		string pasteDataJson = Newtonsoft.Json.JsonConvert.SerializeObject(new PasteBlobJson
		{
			paste = text
		});
		byte[] pasteBlob = Encoding.UTF8.GetBytes(pasteDataJson);
		byte[] _pastePassword = Array.Empty<byte>();
		if (!string.IsNullOrEmpty(password))
			_pastePassword = UTF8Encoding.UTF8.GetBytes(password);
		byte[] urlSecret = new byte[32];
		rng.NextBytes(urlSecret);
		byte[] pastePassphrase = urlSecret;
		if (_pastePassword.Any())
			pastePassphrase = pastePassphrase.Concat(_pastePassword).ToArray();
		int kdfIterations = 100000;
		byte[] kdfSalt = new byte[8];
		rng.NextBytes(kdfSalt);
		Pkcs5S2ParametersGenerator pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
		pdb.Init(pastePassphrase, kdfSalt, kdfIterations);
		byte[] kdfKey = (pdb.GenerateDerivedMacParameters(256) as KeyParameter)!.GetKey();
		int nonceSize = 12;
		byte[] cipherIv = new byte[nonceSize];
		rng.NextBytes(cipherIv);
		string cipherAlgo = "aes";
		string cipherMode = "gcm";
		int cipherTagSize = 128;
		string compressionType = "none";
		int _openDiscussion = openDiscussion ? 1 : 0;
		int _burnAfterReading = burnAfterReading ? 1 : 0;
        byte[] _format = Array.Empty<byte>();
        if (!string.IsNullOrEmpty(format))
            _format = UTF8Encoding.UTF8.GetBytes(format);

        object[] pasteMetaObj = new object[]
		{
			new object[]
			{
				Convert.ToBase64String(cipherIv),
				Convert.ToBase64String(kdfSalt),
				kdfIterations,
				256,
				cipherTagSize,
				cipherAlgo,
				cipherMode,
				compressionType
			},
			format,
			_openDiscussion,
			_burnAfterReading
		};
		string pasteMetaJson = Newtonsoft.Json.JsonConvert.SerializeObject(pasteMetaObj);
		byte[] pasteMeta = Encoding.UTF8.GetBytes(pasteMetaJson);

		GcmBlockCipher cipher = new(new AesEngine());
		AeadParameters parameters = new AeadParameters(
			new KeyParameter(kdfKey), cipherTagSize, cipherIv, pasteMeta);
		cipher.Init(true, parameters);
		byte[] cipherText = new byte[cipher.GetOutputSize(pasteBlob.Length)];
		int len = cipher.ProcessBytes(pasteBlob, 0, pasteBlob.Length, cipherText, 0);
		cipher.DoFinal(cipherText, len);

		return new Tuple<PasteJson, byte[]>(new PasteJson(expire, cipherText, pasteMetaObj), urlSecret);
	}
}

internal class PasteBlobJson
{
	public string? paste;
}

internal class PasteResponse
{
	public string? id;
	public string? deletetoken;
}

internal class PasteJson
{
	public PasteJson(string expire, byte[] ciperText, object[] data)
	{
		ct = Convert.ToBase64String(ciperText);
		meta = new
		{
			expire
		};
		adata = data;
	}
	public object[] adata;
	public int v = 2;
	public object meta;
	public string ct;
}