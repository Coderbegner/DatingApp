using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.api.Data;
using DatingApp.api.Dtos;
using DatingApp.api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.api.Controllers
{
   [Route("api/[controller]")]
    public class AuthController:ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository authRepository,IConfiguration config)
        {
            this._authRepository = authRepository;
            _config = config;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UserForRegisterDto userForRegisterDto)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            userForRegisterDto.username=userForRegisterDto.username.ToLower();

           if(await _authRepository.UserExists(userForRegisterDto.username))
           { 
               return BadRequest("UserName already exists"); 
           }
           var user=new User{
               UserName=userForRegisterDto.username
           };
           await _authRepository.Register(user,userForRegisterDto.password);

           return StatusCode(201);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]UserForLoginDto userForLoginDto)
        {
            var userFromRepo=await 
            _authRepository.Login(userForLoginDto.UserName.ToLower(),userForLoginDto.Password);

            if(userFromRepo==null)
            {
                return Unauthorized();
            }
            //Start making claims

            var claims=new[]
            {
                new Claim(ClaimTypes.NameIdentifier,userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name,userFromRepo.UserName)
               
                
            };
            var key=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds=new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

            var tokendescriptor=new SecurityTokenDescriptor
            {
                Subject=new ClaimsIdentity(claims),
                Expires=DateTime.Now.AddDays(1),
                SigningCredentials=creds
            };

          var tokenHandler=new JwtSecurityTokenHandler();
          var token=tokenHandler.CreateToken(tokendescriptor);

          return Ok(new{
token=tokenHandler.WriteToken(token)
          });
        }
    }
}

