namespace PrivateBinSharp;

public class Paste
{
	public bool IsSuccess { get; internal set; }

	public HttpResponseMessage? Response { get; internal set; }

	public string? Id { get; internal set; }

	public string? Secret { get; internal set; }

	public string? DeleteToken { get; internal set; }

	public string? HostURL { get; internal set; }

	public string ViewURL
		=> HostURL + "?" + Id + "#" + Secret;

	public string DeleteURL
		=> HostURL + "?pasteid=" + Id + "&deletetoken=" + DeleteToken;
}
