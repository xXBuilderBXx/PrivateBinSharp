using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrivateBinSharp
{
    public class Paste
    {
        public bool IsSuccess { get; internal set; }

        public HttpResponseMessage? Response { get; internal set; }

        public string Id { get; internal set; }

        public string Secret { get; internal set; }

        public string DeleteToken { get; internal set; }

        internal string Url;

        public string ViewURL
            => Url + "?" + Id + "#" + Secret;

        public string DeleteURL
            => Url + "?pasteid=" + Id + "&deletetoken=" + DeleteToken;
    }
}
