using BaseLibrary.Dtos;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> jwtConfig,HrDbContext context) : IUserAccount
    {

        async Task<GeneralResponse> IUserAccount.CreateAsync(Register user)
        {
            if(user is null) return new GeneralResponse(false, "User is null");

            var checkUser = await FindUserByEmail(user.Email);
            if(checkUser != null) return new GeneralResponse(false, "User already exists");

            var newUser = await AddToDatabase(new AppUser()
            {
                Email = user.Email,
                Fullname = user.FullName,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

        }

        Task<LoginResponse> IUserAccount.SignInAsync(Login user)
        {
            throw new NotImplementedException();
        }

        private async Task<AppUser> FindUserByEmail(string email) =>
            await context.AppUsers.FirstOrDefaultAsync(x => x.Email.Equals(email,StringComparison.OrdinalIgnoreCase));

        private async Task<AppUser> AddToDatabase(AppUser user)
        {
            await context.AppUsers.AddAsync(user);
            await context.SaveChangesAsync();
            return user;
        }


    }
}
