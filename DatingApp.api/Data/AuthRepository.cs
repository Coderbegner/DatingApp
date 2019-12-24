using System;
using System.Threading.Tasks;
using DatingApp.api.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.api.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _dataContext;

        public AuthRepository(DataContext DataContext)
    {
            _dataContext = DataContext;
        }
        public async Task<User> Login(string username, string password)
        {
            var user=await _dataContext.Users.FirstOrDefaultAsync(x=>x.UserName==username);
            
            if(user==null)
            {
                return null;
            }

            if(!ValidatePassword(password,user.PasswordHash,user.PasswordSalt))
            {
                return null;
            }
            return user;
        }

        private bool ValidatePassword(string password, byte[] passwordHash, byte[] passwordSalt)
        {
             using(var hmac=new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                var computedHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                if(computedHash.Length!=passwordHash.Length)
                {
                    return false;
                }
                for(int i=0;i<computedHash.Length;i++)
                {
                    if(computedHash[i]!=passwordHash[i])
                    {
                        return false;
                    }
                }
              return true;
            }
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash,passwordSalt;
            CreatePassWordHash(password, out passwordHash, out passwordSalt);
            user.PasswordHash=passwordHash;
            user.PasswordSalt=passwordSalt;
            await _dataContext.Users.AddAsync(user);
            await _dataContext.SaveChangesAsync();
            return user;

        }

        private void CreatePassWordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac=new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt=hmac.Key;
                passwordHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }

        }

        public async Task<bool> UserExists(string username)
        {
            var user= await _dataContext.Users.AnyAsync(x=>x.UserName==username);
            if(user)
            {
          return true;
            }
            return false;
        }
    }
}