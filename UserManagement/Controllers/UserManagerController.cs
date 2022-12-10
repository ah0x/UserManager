using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserManagement.Interfaces;
using UserManagement.UserManager.AuthModels;

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
            var users = await _userManagerService.GetAllUsers();
            return View(users);
        }

        [HttpGet]
        public async Task<ActionResult> UserRole(string userId)
        {
            var userRolesVM = new List<UserRolesViewModel>();
            var user = await _userManager.FindByIdAsync(userId);

            foreach (var role in _roleManager.Roles)
            {
                var userRoleVM = new UserRolesViewModel()
                {
                    RoleName = role.Name,
                };

                if (await _userManager.IsInRoleAsync(user, userRoleVM.RoleName))
                {
                    userRoleVM.Selected = true;
                }
                else
                {
                    userRoleVM.Selected = false;
                }

                userRolesVM.Add(userRoleVM);
            }

            var model = new ManageUserRoleViewModel()
            {
                UserId = userId,
                UserRoles = userRolesVM
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> UserRole([FromForm]ManageUserRoleViewModel model)
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
            result = await _userManager.AddToRolesAsync(user, model.UserRoles.Where(a => a.Selected == true).Select(x => x.RoleName));

            var currentUser = await _userManager.GetUserAsync(User);

            await _signInManager.RefreshSignInAsync(currentUser);
            //await DefaultUsers.SeedAdminUsersAsync(_userManager, _roleManager);

            return RedirectToAction(nameof(Index), new { userId = model.UserId });
        }
    }
}
