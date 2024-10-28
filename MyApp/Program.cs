using System.Net;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using ServiceStack.Blazor;
using MyApp.Data;
using MyApp.Components;
using MyApp.Components.Account;
using MyApp.ServiceInterface;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var config = builder.Configuration;

// Add services to the container.
services.AddRazorComponents()
    .AddInteractiveServerComponents();

services.AddCascadingAuthenticationState();
services.AddScoped<IdentityUserAccessor>();
services.AddScoped<IdentityRedirectManager>();
services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

services.AddAuthentication("AzureAD")
    .AddOpenIdConnect("AzureAD", options =>
    {
        builder.Configuration.Bind("AzureAd", options);
        options.SignInScheme = IdentityConstants.ExternalScheme;
        var tenantId = config["AzureAd:TenantId"];
        // options.Authority = $"https://login.microsoftonline.com/{TENANT ID}/v2.0/";
        // options.ClientId = "123133a4-23f1-418c-31d4-3ee1312c1123";
        // options.Scope.Add(OpenIdConnectScope.OfflineAccess);
        options.ResponseType = OpenIdConnectResponseType.Code;
        ;
        options.SaveTokens = true;
        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
        options.TokenValidationParameters.RoleClaimType = "roles";
    })
    // .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
    .AddIdentityCookies(options => options.DisableRedirectsForApis());
services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("App_Data"));

// ConfigureCookieOidcRefresh attaches a cookie OnValidatePrincipal callback to get
// a new access token when the current one expires, and reissue a cookie with the
// new access token saved inside. If the refresh fails, the user will be signed
// out. OIDC connect options are set for saving tokens and the offline access
// scope.
// services.ConfigureCookieOidcRefresh(CookieAuthenticationDefaults.AuthenticationScheme, "AzureAD");

services.AddDatabaseDeveloperPageExceptionFilter();

services.AddIdentityCore<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();
// Uncomment to send emails with SMTP, configure SMTP with "SmtpConfig" in appsettings.json
// services.AddSingleton<IEmailSender<ApplicationUser>, EmailSender>();
// services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, AdditionalUserClaimsPrincipalFactory>();
services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, AdditionalUserClaimsPrincipalFactory>();

var baseUrl = builder.Configuration["ApiBaseUrl"] ??
    (builder.Environment.IsDevelopment() ? "https://localhost:5001" : "http://" + IPAddress.Loopback);
services.AddScoped(c => new HttpClient { BaseAddress = new Uri(baseUrl) });
services.AddBlazorServerApiClient(baseUrl);
services.AddLocalStorage();

// Register all services
services.AddServiceStack(typeof(MyServices).Assembly);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.UseServiceStack(new AppHost(), options => {
    // options.AuthenticationSchemes = "Identity.Application,Bearer";
    options.MapEndpoints();
});

BlazorConfig.Set(new()
{
    Services = app.Services,
    JSParseObject = JS.ParseObject,
    IsDevelopment = app.Environment.IsDevelopment(),
    EnableLogging = app.Environment.IsDevelopment(),
    EnableVerboseLogging = app.Environment.IsDevelopment(),
});

app.Run();
