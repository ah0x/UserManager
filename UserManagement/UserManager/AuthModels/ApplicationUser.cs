using Microsoft.AspNetCore.Identity;

namespace UserManagement.UserManager.AuthModels
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public string? ProfilePicture { get; set; }
    }
}
