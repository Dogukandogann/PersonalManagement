using BaseLibrary.Dtos;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using BCrypt.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> jwtConfig,HrDbContext context) : IUserAccount
    {

        async Task<GeneralResponse> IUserAccount.CreateAsync(Register user)
        {

            try
            {
                if (user is null) return new GeneralResponse(false, "User is null");

                if (await FindUserByEmail(user.Email) != null)
                    return new GeneralResponse(false, "User already exists");            
                 
                var newUser = await AddToDatabase(new AppUser()
                {
                    Email = user.Email,
                    Fullname = user.FullName,
                    Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
                });

                var checkAdminRole = await context.SystemRoles.FirstOrDefaultAsync(x => x.Name.Equals(Constants.Admin));
                if (checkAdminRole is null)
                {
                    var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
                    await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = newUser.Id });
                    return new GeneralResponse(true, "Account created successfully");
                };

                var checkUserRole = await context.SystemRoles.FirstOrDefaultAsync(x => x.Name.Equals(Constants.User));
                SystemRole response = new();
                if (checkUserRole is null)
                {
                    response = await AddToDatabase(new SystemRole() { Name = Constants.User });
                    await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = newUser.Id });
                }
                else
                {
                    await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = newUser.Id });
                }
                return new GeneralResponse(true, "Account created successfully");
            }
            catch (Exception ex)
            {

                return new GeneralResponse(false, $"Account could not be created {ex.Message}");
            }
           

        }


        async Task<LoginResponse> IUserAccount.SignInAsync(Login user)
        {
            try
            {
                if (user is null) return new LoginResponse(false,"Model is empty");
                var appUser = await FindUserByEmail(user.Email);
                if (appUser is null) return new LoginResponse(false, "User does not exist");
                if (!BCrypt.Net.BCrypt.Verify(user.Password,appUser.Password)) return new LoginResponse(false, "Email/Password is not valid");
                var getUserRole = await GetUserRole(appUser.Id);
                if (getUserRole is null) return new LoginResponse(false, "User role not found");
                var getRoleName = await GetUserName(getUserRole.RoleId);
                if (getRoleName is null) return new LoginResponse(false, "Role not found");
                string jwtToken = GenerateToken(appUser,getRoleName.Name);
                string refreshToken = GenerateRefreshToken();
                
                var findUser = await context.refreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == appUser.Id);
                if (findUser is not null)
                {
                    findUser.RefreshToken = refreshToken;
                    await context.SaveChangesAsync();
                }
                else
                {
                    await AddToDatabase(new RefreshTokenInfo() { UserId = appUser.Id, RefreshToken = refreshToken });
                }
                return new LoginResponse(true, "Login successful", jwtToken, refreshToken);


            }
            catch (Exception ex)
            {

                return new LoginResponse(false, $"Login failed {ex.Message}");
            }
        }

        private string GenerateToken(AppUser user,string role)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Value.Secret));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var userClaims = new[]
                {
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Name,user.Fullname),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.Role,role)
            };

                var token = new JwtSecurityToken(issuer: jwtConfig.Value.Issuer, audience: jwtConfig.Value.Audience, claims: userClaims, expires: DateTime.UtcNow.AddDays(1), signingCredentials: credentials);
                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (SecurityTokenException ex)
            {

                return $"Failed to generate token.Please try again.{ex.Message}";
            }
            catch (Exception ex)
            {
                return $"An unexpected error occurred. Please try again later.{ex.Message}";
            }
           
        }

        private async Task<UserRole> GetUserRole(int userId) => await context.UserRoles.FirstOrDefaultAsync(x => x.UserId == userId);
        private async Task<SystemRole> GetUserName(int roleId) => await context.SystemRoles.FirstOrDefaultAsync(x => x.Id == roleId);
        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<AppUser> FindUserByEmail(string email) =>
            await context.AppUsers.FirstOrDefaultAsync(x => x.Email.ToLower().Equals(email.ToLower()));

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = context.Add(model);
            await context.SaveChangesAsync();
            return (T)result.Entity;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            try
            {
                if (token is null) return new LoginResponse(false,"Model is empty");
                var findToken = await context.refreshTokenInfos.FirstOrDefaultAsync(x => x.RefreshToken.Equals(token.Token));
                if (findToken is null) return new LoginResponse(false, "Token not found");

                var user = await context.AppUsers.FirstOrDefaultAsync(x => x.Id == findToken.UserId);
                if (user is null) return new LoginResponse(false, "Refresh token could not be generated because user not found");

                var userRole = await GetUserRole(user.Id);
                var userRoleName = await GetUserName(userRole.RoleId);
                string jwtToken = GenerateToken(user, userRoleName.Name);
                string refreshToken = GenerateRefreshToken();

                var updateRefreshToken = await context.refreshTokenInfos.FirstOrDefaultAsync(x => x.RefreshToken.Equals(token.Token));
                if(updateRefreshToken is null) return new LoginResponse(false, "Refresh token could not be generated because user has not sign in");

                updateRefreshToken.RefreshToken = refreshToken;
                await context.SaveChangesAsync();
                return new LoginResponse(true, "Refresh token generated successfully", jwtToken, refreshToken);
            }
            catch (Exception ex )
            {

                return new LoginResponse(false, $"Refresh token failed {ex.Message}");
            }
        }
    }
}
