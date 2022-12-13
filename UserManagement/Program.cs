using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using UserManagement.Data;
using UserManagement.Helper;
using UserManagement.Interfaces;
using UserManagement.Service;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Permission;
using UserManagement.UserManager.Seeds;
using static UserManagement.UserManager.Statics.Permissions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

//builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddDefaultIdentity<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRoles<IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultUI().AddDefaultTokenProviders();

//Role and Permission Configuration
builder.Services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RolesPolicy.View", policy => policy.RequireClaim(  "Permission", RolesPolicy.View));
    options.AddPolicy("RolesPolicy.Create", policy => policy.RequireClaim("Permission", RolesPolicy.Create));
    options.AddPolicy("RolesPolicy.Edit", policy => policy.RequireClaim(  "Permission", RolesPolicy.Edit));
    options.AddPolicy("RolesPolicy.Delete", policy => policy.RequireClaim("Permission", RolesPolicy.Delete));

    options.AddPolicy("UserPolicy.View", policy => policy.RequireClaim("Permission", UserPolicy.View));
    options.AddPolicy("UserPolicy.Create", policy => policy.RequireClaim("Permission", UserPolicy.Create));
    options.AddPolicy("UserPolicy.Edit", policy => policy.RequireClaim("Permission", UserPolicy.Edit));
    options.AddPolicy("UserPolicy.Delete", policy => policy.RequireClaim("Permission", UserPolicy.Delete));
});


builder.Services.AddScoped<IUserManagerService, UserManagerService>();

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

//Seed User
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var loggerFactory = services.GetRequiredService<ILoggerFactory>();
    var logger = loggerFactory.CreateLogger("app");

    try
    {
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        await DefaultRoles.SeedAsync(userManager, roleManager);

        await DefaultUsers.SeedSuperAdminUsersAsync(userManager, roleManager);

        logger.LogInformation("Seeding Finished");
        logger.LogInformation("Application Starting");
    }
    catch (Exception e)
    {
        logger.LogWarning(e, "An error occurred seeding the DB");
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
