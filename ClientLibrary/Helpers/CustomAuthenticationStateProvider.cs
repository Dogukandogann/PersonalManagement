using BaseLibrary.Dtos;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ClientLibrary.Helpers
{
    public class CustomAuthenticationStateProvider(LocalStorageService localStorageService) : AuthenticationStateProvider
    {
        
        private readonly ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var stringToken =await localStorageService.GetToken();
            if (string.IsNullOrEmpty(stringToken)) return await Task.FromResult(new AuthenticationState(_anonymous));

            var deserializeToken = Serializations.DeserializeObjString<UserSession>(stringToken);
            if (deserializeToken is null) return await Task.FromResult(new AuthenticationState(_anonymous));

            var getUserClaims = DecrypToken(deserializeToken.Token);
            if(getUserClaims is null) return await Task.FromResult(new AuthenticationState(_anonymous));

            var claimsPrincipal = SetClaimsPrincipal(getUserClaims);
            return await Task.FromResult(new AuthenticationState(claimsPrincipal));
        }

        public async Task UpdateAuthenticationState(UserSession userSession)
        {
            var claimsPrincipal = new ClaimsPrincipal();
            if(userSession.Token !=null || userSession.RefreshToken != null)
            {
                var serizalizeToken = Serializations.SerializeObj(userSession);
                await localStorageService.SetToken(serizalizeToken);
                var userClaims = DecrypToken(userSession.Token);
                claimsPrincipal =SetClaimsPrincipal(userClaims);
            }
            else
            {
                await localStorageService.RemoveToken();
            }
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }
        public static CustomUserClaims DecrypToken(string jwtToken)
        {
            if (string.IsNullOrEmpty(jwtToken)) return new CustomUserClaims();

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);

            var userId = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            var name = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            var eMail = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            var role = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
            return new CustomUserClaims(userId?.Value, name?.Value, eMail?.Value, role?.Value);
        }

        public static ClaimsPrincipal SetClaimsPrincipal(CustomUserClaims claims)
        {
            if(claims.eMail is null) return new ClaimsPrincipal();
            return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> 
            { 
                new(ClaimTypes.NameIdentifier,claims.id),
                new(ClaimTypes.Name,claims.name),
                new(ClaimTypes.Email,claims.eMail),
                new(ClaimTypes.Role,claims.role),
            }, "JwtAuth"
            ));
        }
    }
}
