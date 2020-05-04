using AuthServer.Infrastructure;
using AuthServer.Infrastructure.Constants;
using AuthServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> userManager;

        public AccountController(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }

        [HttpPost]
        [Route("api/[controller]")]
        public async Task<IActionResult> Register([FromBody]RegisterRequestViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = model.ConvertToAppUser();

            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("userName", user.UserName));
            await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("name", user.Name));
            await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("email", user.Email));
            await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("role", Roles.Consumer));

            return Ok(new RegisterResponseViewModel(user));
        }
    }
}
