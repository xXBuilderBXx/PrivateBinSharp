namespace PrivateBinSharp;

/// <summary>
/// Paste data created from the PrivateBin host and API.
/// </summary>
public class Paste
{
	/// <summary>
	/// Paste was created successfully.
	/// </summary>
	public bool IsSuccess { get; internal set; }

	/// <summary>
	/// The http response from the PrivateBin host API.
	/// </summary>
	public HttpResponseMessage? Response { get; internal set; }

	/// <summary>
	/// ID of the paste data.
	/// </summary>
	public string? Id { get; internal set; }

	/// <summary>
	/// Secret of the paste data.
	/// </summary>
	public string? Secret { get; internal set; }

	/// <summary>
	/// Deletion token of the paste data.
	/// </summary>
	public string? DeleteToken { get; internal set; }

	/// <summary>
	/// The host URL used for the request.
	/// </summary>
	public string? HostURL { get; internal set; }

	/// <summary>
	/// The URL used to view the paste data.
	/// </summary>
	public string ViewURL
		=> HostURL + "?" + Id + "#" + Secret;

	/// <summary>
	/// The URL used to delete the paste data.
	/// </summary>
	public string DeleteURL
		=> HostURL + "?pasteid=" + Id + "&deletetoken=" + DeleteToken;
}
