using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BaseLibrary.Dtos
{
    public record CustomUserClaims(string id=null,string name=null,string eMail=null,string role=null);
    
}
