using System.Security.Claims;
using AuthenticationServerApi.Models;
using AuthenticationServerApi.Models.Requests;
using AuthenticationServerApi.Models.Responses;
using AuthenticationServerApi.Services.Authenticators;
using AuthenticationServerApi.Services.RefreshTokenRepositories;
using AuthenticationServerApi.Services.TokenValidators;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationServerApi.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserManager<User> _userRepository;
        private readonly Authenticator _authenticator;
        private readonly RefreshTokenValidator _refreshTokenValidator;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthController(UserManager<User> userRepository, RefreshTokenValidator refreshTokenValidator, IRefreshTokenRepository refreshTokenRepository, Authenticator authenticator)
        {
            _userRepository = userRepository;
            _refreshTokenValidator = refreshTokenValidator;
            _refreshTokenRepository = refreshTokenRepository;
            _authenticator = authenticator;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest registerRequest)
        {
            if (!ModelState.IsValid)
                return BadRequestModelState();

            if (registerRequest.Password != registerRequest.ConfirmPassword)
                return BadRequest(new ErrorResponse("Password does not match confirm password"));
            
        
            User registrationUser = new User()
            {
                Email = registerRequest.Email,
                UserName = registerRequest.Username
            };

           IdentityResult result = await _userRepository.CreateAsync(registrationUser, registerRequest.Password);
           if (!result.Succeeded)
           {
               var errorDescriber = new IdentityErrorDescriber();
               var primaryError = result.Errors.FirstOrDefault();
               
               switch (primaryError.Code)
               {
                   case nameof(errorDescriber.DuplicateEmail):
                       return Conflict(new ErrorResponse("Email already exists"));
                   case nameof(errorDescriber.DuplicateUserName):
                       return Conflict(new ErrorResponse("Username already exists"));
               }
           }
           
            return Ok();

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            if (!ModelState.IsValid)
                return BadRequestModelState();

            User user = await _userRepository.FindByNameAsync(loginRequest.Username);
            if (user == null)
                return Unauthorized();

            bool isCorrectPassword = await _userRepository.CheckPasswordAsync(user, loginRequest.Password);
            if(!isCorrectPassword)
                return Unauthorized();

            AuthenticatedUserResponse response = await _authenticator.Authenticate(user);
            return Ok(response);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest refreshRequest)
        {
            if (!ModelState.IsValid)
                return BadRequestModelState();

            bool isValidRefreshToken = _refreshTokenValidator.Validate(refreshRequest.RefreshToken);
            if (!isValidRefreshToken)
                return BadRequest(new ErrorResponse("Invalid refresh token"));

            RefreshToken refreshTokenDTO = await _refreshTokenRepository.GetByToken(refreshRequest.RefreshToken);
            if (refreshTokenDTO == null)
            {
                return NotFound(new ErrorResponse("Invalid refresh token"));
            }

            await _refreshTokenRepository.Delete(refreshTokenDTO.Id);

            User user = await _userRepository.FindByIdAsync(refreshTokenDTO.UserId.ToString());
            if(user == null)
                return NotFound(new ErrorResponse("User not found"));


            AuthenticatedUserResponse response = await _authenticator.Authenticate(user);
            return Ok(response);
        }

        [Authorize]
        [HttpDelete("logout")]
        public async Task<IActionResult> Logout()
        {
            string rawUserId = HttpContext.User.FindFirstValue("id");

            if (!Guid.TryParse(rawUserId, out Guid userId))
                return Unauthorized();

            await _refreshTokenRepository.DeleteAll(userId);

            return NoContent();
        }

        private IActionResult BadRequestModelState()
        {
            IEnumerable<string> errorMessages =
                ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
            
            return BadRequest(new ErrorResponse(errorMessages));
        }
    }
}
