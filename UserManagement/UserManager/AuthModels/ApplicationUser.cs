﻿using Microsoft.AspNetCore.Identity;

namespace UserManagement.UserManager.AuthModels
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
    }
}
