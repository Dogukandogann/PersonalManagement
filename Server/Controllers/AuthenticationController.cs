using BaseLibrary.Dtos;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationControlle(IUserAccount userAccount) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync(Register user)
        {
            try
            {

                if (user is null) return BadRequest("User is null");
                var result = await userAccount.CreateAsync(user);
                return Ok(result);

            }
            catch (Exception ex)
            {

                return BadRequest($"Account could not be created {ex.Message}");

            }
        }
        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login user)
        {
            try
            {
                if (user is null) return BadRequest("Model is empty");
                var result = await userAccount.SignInAsync(user);
                return Ok(result);
            }
            catch (Exception ex)
            {

                return BadRequest($"Login failed {ex.Message}");
            }
        }
    }
}
