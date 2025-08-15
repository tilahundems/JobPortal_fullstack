using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JobPortalAPI;

     [ApiController]
    [Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _config;

 public AuthController(
    UserManager<IdentityUser> userManager,RoleManager<IdentityRole> roleManager,
    IConfiguration config
    )
        {
             _userManager = userManager;
             _roleManager = roleManager;
             _config = config;
        }

       [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDTO dto) 
    {
          var existing = await _userManager.FindByNameAsync(dto.Username);
          if(existing == null)
          return BadRequest("Username Already Exists");

          var user = new IdentityUser {UserName = dto.Username};
          var result = await  _userManager.CreateAsync(user,dto.Password);
          if(!result.Succeeded)
          return BadRequest(result.Errors);

        var role = string.IsNullOrWhiteSpace(dto.Role) ? "Applicant" : dto.Role!;
            if (!await _roleManager.RoleExistsAsync(role))
                await _roleManager.CreateAsync(new IdentityRole(role));


         await _userManager.AddToRoleAsync(user,role);
        return Ok(new { message = "Registered", role });
        
    }
            [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO dto)
        {
             var user = await _userManager.FindByNameAsync(dto.Username);
             if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
                return Unauthorized("Invalid credentials");
                var roles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            foreach (var r in roles) claims.Add(new Claim(ClaimTypes.Role, r));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                expires: DateTime.UtcNow.AddHours(2),
                claims: claims,
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expires = token.ValidTo,
                roles
            });


        }
}
