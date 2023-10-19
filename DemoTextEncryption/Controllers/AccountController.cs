using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace DemoTextEncryption.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        public static string UserName { get; set; } = string.Empty;
        public static string HashedPassword { get; set; } = string.Empty;

        // Using Normal Encryption

        [HttpGet("Default/{username}/{password}")]
        public ActionResult<string> HashPassword(string username, string password)
        {
            byte[] salt = new byte[16];
            using (var randomGenerator = RandomNumberGenerator.Create())
            {
                randomGenerator.GetBytes(salt);
            }
            var rfcPassword = new Rfc2898DeriveBytes(password, salt, 1000, HashAlgorithmName.SHA1);
            byte[] rfcPasswordHash = rfcPassword.GetBytes(20);

            byte[] passwordHash = new byte[36];
            Array.Copy(salt, 0, passwordHash, 0, 16);
            Array.Copy(rfcPasswordHash, 0, passwordHash, 16, 20);
            string hashedPassword = Convert.ToBase64String(passwordHash);

            UserName = username; HashedPassword = hashedPassword;
            return ($"Username:{username}{Environment.NewLine}Password:{hashedPassword}");
        }


        //Verify Password
        [HttpGet("Default/VerifyPassword/{password}")]
        public ActionResult<bool> VerifyPassword(string password)
        {
            byte[] PasswordHash = Convert.FromBase64String(HashedPassword);
            byte[] salt = new byte[16];
            Array.Copy(PasswordHash, 0, salt, 0, 16);
            var rfcPassword = new Rfc2898DeriveBytes(password, salt, 1000, HashAlgorithmName.SHA1);
            byte[] rfcPasswordHash = rfcPassword.GetBytes(20);
            for (int i = 0; i < rfcPasswordHash.Length; i++)
            {
                if (PasswordHash[i + 16] != rfcPasswordHash[i])
                    return false;
            }
            return true;
        }




        //Using BCrypt.Net Next

        [HttpGet("BCrypt/{username}/{password}")]
        public ActionResult<string> HashPssword1(string username, string password)
        {
            //var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);
            var hashedPassword = BCrypt.Net.BCrypt.EnhancedHashPassword(password, hashType: BCrypt.Net.HashType.SHA512);
            UserName = username; HashedPassword = hashedPassword;
            return ($"Username:{username}{Environment.NewLine}Password:{hashedPassword}");
        }

        //Verify Password
        [HttpGet("BCrypt/VerifyPassword/{password}")]
        public ActionResult<bool> VerifyPassword1(string password)
        {
            //var hashedPassword = BCrypt.Net.BCrypt.Verify(password, HashedPassword);
            var hashedPassword = BCrypt.Net.BCrypt.EnhancedVerify(password, HashedPassword, hashType: BCrypt.Net.HashType.SHA512);
            return hashedPassword is true ? true : false;
        }
    }
}
