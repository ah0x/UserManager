using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserManagement.Helper;
using UserManagement.Interfaces;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Statics;

namespace UserManagement.Controllers
{
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

        [HttpGet]
        public async Task<ActionResult> UserRole(string userId)
        {
            return View(await _userManagerService.GetUserRoleByUserId(userId));
        }

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

        [HttpGet]
        public async Task<ActionResult> AddRole()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }

        [HttpPost]
        public async Task<ActionResult> AddRole(string roleName, List<RoleClaimViewModel> permissions)
        {
            if (roleName != null)
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));
            }
            return RedirectToAction(nameof(Index));
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

        [HttpGet]
        public async Task<IActionResult> Edit(string userId)
        {
            return View(await _userManagerService.GetUserById(userId));
        }
        [HttpPost]
        public async Task<IActionResult> Edit(string UserId, ApplicationUser model)
        {
            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                return NotFound();
            }

            user.FullName = model.FullName;
            user.PhoneNumber = model.PhoneNumber;
            await _userManager.UpdateAsync(user);
            return RedirectToAction("Index");
        }

        public async Task<IActionResult> Delete(string UserId)
        {
            var user = await _userManagerService.GetUserById(UserId);
            if(user == null)
            {
                return BadRequest();
            }
            await _userManager.DeleteAsync(user);
            return RedirectToAction("Index");
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Create(ApplicationUser user, string? MakkeSuper)
        {
            if (ModelState.IsValid)
            {
                user.Id = Guid.NewGuid().ToString();
                user.UserName = user.Email;
                //await _userStore.SetUserNameAsync(user, user.Email, CancellationToken.None);
                IdentityResult result = await _userManager.CreateAsync(user, user.PasswordHash);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, Roles.Custmer.ToString());
                    if (MakkeSuper == "on")
                    {
                        await _userManager.AddToRoleAsync(user, Roles.SuperAdmin.ToString());
                    }
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
