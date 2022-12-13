using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using UserManagement.Helper;
using UserManagement.Interfaces;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Statics;
using static UserManagement.UserManager.Statics.Permissions;

namespace UserManagement.Controllers
{
    [Authorize]
    public class UserManagerController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IUserManagerService _userManagerService;

        public UserManagerController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IUserManagerService userManagerService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _userManagerService = userManagerService;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _userManagerService.GetAllUsers());
        }

        [Authorize(Policy = RolesPolicy.Create)]
        [HttpGet]
        public async Task<ActionResult> UserRole(string userId)
        {
            return View(await _userManagerService.GetUserRoleByUserId(userId));
        }

        [Authorize(Policy = RolesPolicy.Create)]
        [HttpPost]
        public async Task<IActionResult> UserRole(ManageUserRoleViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return View(model);
            }

            var roles = await _userManager.GetRolesAsync(user);
            if (roles == null)
            {
                return View();
            }

            var result = await _userManager.RemoveFromRolesAsync(user, roles);
            await _userManager.AddToRolesAsync(user, model.UserRoles.Where(a => a.Selected == true).Select(x => x.RoleName));

            var currentUser = await _userManager.GetUserAsync(User);

            await _signInManager.RefreshSignInAsync(currentUser);

            return RedirectToAction(nameof(Index));
        }

        [Authorize(Policy = RolesPolicy.View)]
        [HttpGet]
        public async Task<ActionResult> AddRole()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }

        [Authorize(Policy = RolesPolicy.Create)]
        [HttpPost]
        public async Task<ActionResult> AddRole(string roleName, List<RoleClaimViewModel> permissions)
        {
            if (roleName is null)
            {
                TempData["Message"] = "Can't Add Empty Role";
                return RedirectToAction(nameof(AddRole));
            }
            await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));
            return RedirectToAction(nameof(AddRole));
        }

        [Authorize(Policy = RolesPolicy.Edit)]
        [HttpGet]
        public async Task<IActionResult> EditRole(string roleId)
        {
            var role = await _userManagerService.GetRoleByRoleId(roleId);

            if (role is null)
            {
                TempData["Message"] = "Can't Edit Role";
                return RedirectToAction("AddRole");
            }
            return View(role);
        }

        [Authorize(Policy = RolesPolicy.Edit)]
        [HttpPost]
        public async Task<IActionResult> EditRole(string roleId,IdentityRole model)
        {
            var role = await _userManagerService.GetRoleByRoleId(roleId);

            if (role is null)
            {
                TempData["Message"] = "Can't Edit Role";
                return RedirectToAction(nameof(AddRole));
            }

            role.Name = model.Name;
            await _roleManager.UpdateAsync(role);
            return RedirectToAction(nameof(AddRole));
        }

        [Authorize(Policy = RolesPolicy.Delete)]
        [HttpGet]
        public async Task<IActionResult> DeleteRole(string roleId)
        {
            var role = await _userManagerService.GetRoleByRoleId(roleId);

            if (role is null)
            {
                TempData["Message"] = "Can't Delete Role";
                return RedirectToAction("AddRole");
            }

            if (_userManagerService.IsRoleInUse(role.Name).Result == true)
            {
                TempData["Message"] = "Can't Delete Used Role ";
                return RedirectToAction("AddRole");
            }

            await _roleManager.DeleteAsync(role);
            return RedirectToAction("AddRole");
        }


        [HttpGet]
        public async Task<ActionResult> Permission(string roleId)
        {
            return View(await _userManagerService.GetPermissionsByRoleId(roleId));
        }

        [HttpPost]
        public async Task<ActionResult> Permission(PermissionViewModel model)
        {
            var role = await _roleManager.FindByIdAsync(model.RoleId);
            var claims = await _roleManager.GetClaimsAsync(role);
            foreach (var claim in claims)
            {
                await _roleManager.RemoveClaimAsync(role, claim);
            }
            var selectedClaims = model.RoleClaims.Where(a => a.Selected).ToList();
            foreach (var claim in selectedClaims)
            {
                await _roleManager.AddPermissionClaim(role, claim.Value);
            }
            return RedirectToAction("Index", new { roleId = model.RoleId });
        }

        [Authorize(Policy = UserPolicy.Create)]
        public IActionResult CreateUser()
        {
            ViewData["Roles"] = new SelectList(_roleManager.Roles, "Id", "Name");
            return View();
        }

        [Authorize(Policy = UserPolicy.Create)]
        [HttpPost]
        public async Task<IActionResult> CreateUser(ApplicationUser user, string roleId, IFormFile file)
        {

            if (ModelState.IsValid)
            {
                user.ProfilePicture = await _userManagerService.SaveUserImage(file); ;
                user.Id = Guid.NewGuid().ToString();
                user.UserName = user.Email;

                IdentityResult result = await _userManager.CreateAsync(user, user.PasswordHash);
                if (result.Succeeded)
                {
                    var role = await _userManagerService.GetRoleByRoleId(roleId);
                    if (role is null)
                    {
                        TempData["Message"] = "Role Not Valid";
                        return View();
                    }
                    await _userManager.AddToRoleAsync(user, role.Name);
                }
                else
                {
                    TempData["Message"] = "Invalid Saving";
                    return View();
                }
                return RedirectToAction("Index");
            }
            return View();
        }

        [Authorize(Policy = UserPolicy.Edit)]
        [HttpGet]
        public async Task<IActionResult> EditUser(string userId)
        {
            return View(await _userManagerService.GetUserById(userId));
        }

        [Authorize(Policy = UserPolicy.Edit)]
        [HttpPost]
        public async Task<IActionResult> EditUser(string UserId, ApplicationUser model, IFormFile file)
        {
            var user = await _userManagerService.GetUserById(UserId);
            if (user == null)
            {
                return NotFound();
            }

            if(file is not null)
            {
                user.ProfilePicture = await _userManagerService.SaveUserImage(file);
            }
            
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PhoneNumber = model.PhoneNumber;
            await _userManager.UpdateAsync(user);
            return RedirectToAction("Index");
        }

        [Authorize(Policy = UserPolicy.Delete)]
        public async Task<IActionResult> DeleteUser(string UserId)
        {
            var user = await _userManagerService.GetUserById(UserId);
            if(user == null)
            {
                return BadRequest();
            }
            await _userManager.DeleteAsync(user);
            return RedirectToAction("Index");
        }

        [Authorize(Policy = UserPolicy.View)]
        public async Task<IActionResult> DetailsUser(string UserId)
        {
            var role = _userManagerService.GetUserRoleByUserId(UserId).Result.UserRoles;

            List<string> strings = new List<string>();
            foreach (var item in role)
            {
                if(item.Selected == true)
                {
                    strings.Add(item.RoleName);
                }
            }

            ViewData["Roles"] = strings;
            var user = await _userManagerService.GetUserById(UserId);
            if (user == null)
            {
                return BadRequest();
            }
            return View(user);
        }

        
        public async Task<IActionResult> ResetPassword(string UserId)
        {
            var user = await _userManagerService.GetUserById(UserId);
            ViewBag.UserId = UserId;
            if (user == null)
            {
                return NotFound();
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(string? UserId, string Password, string ConfirmPassword)
        {
            if (string.IsNullOrEmpty(Password))
            {
                return BadRequest();
            }
            if (string.IsNullOrEmpty(ConfirmPassword))
            {
                return BadRequest();
            }
            if (ConfirmPassword == Password)
            {
                var user = await _userManager.FindByIdAsync(UserId);
                var newPassword = _userManager.PasswordHasher.HashPassword(user, Password);
                user.PasswordHash = newPassword;
                await _userManager.UpdateAsync(user);
            }
            return RedirectToAction("Index");
        }

        public async Task<IActionResult> Look(string UserId)
        {
            var user = await _userManagerService.GetUserById(UserId);
            if (user != null)
            {
                if (user.EmailConfirmed == false)
                {
                    user.EmailConfirmed = true;
                }
                else
                {
                    user.EmailConfirmed = false;
                }
                await _userManager.UpdateAsync(user);
            }
            return RedirectToAction("Index");
        }
    }
}
