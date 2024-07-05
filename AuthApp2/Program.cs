using AuthApp2.Authentication;
using AuthApp2.Authorization.PolicyBasedAuthorization;
using AuthApp2.Authorization.PolicyBasedAuthorization.AuthorizationPolicies;
using AuthApp2.Authorization.PolicyBasedAuthorization.ClaimTypes;
using AuthApp2.Authorization.PolicyBasedAuthorization.Requirements;
using AuthApp2.Authorization.RoleBasedAuthorization.Roles;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddDbContext<AppDbContext>();

//Add Identity Roles
builder.Services.AddIdentityCore<AppUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

//Add Auhthentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        var secret = builder.Configuration["JwtConfig:Secret"];
        var issuer = builder.Configuration["JwtConfig:ValidIssuer"];
        var audience = builder.Configuration["JwtConfig:ValidAudiences"];
        if(secret is null ||  issuer is null || audience is null)
        {
            throw new ApplicationException("Jwt is not set in the Configuration");
        }
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
        };
    });

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

//Configuring UI swagger
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "Jwt Authorization header using the Beare scheme .example :\"Authorization :Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey, 
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string  []{ }
        },
    });
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AppAuthorizationPolicies.SpecialPremiumContent, policy =>
    {
        policy.Requirements.Add(new SpecialPremiumContentRequirement("Uzbekistan"));
    });
});
builder.Services.AddSingleton<IAuthorizationHandler,SpecialPremiumContentAuthorizationHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

// Check if the roles exist, if not, create them
using (var serviceScope = app.Services.CreateScope())
{
    var services = serviceScope.ServiceProvider;

    // Ensure the database is created.
    var dbContext = services.GetRequiredService<AppDbContext>();
    //dbContext.Database.EnsureDeleted();
    dbContext.Database.EnsureCreated();

    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    if (!await roleManager.RoleExistsAsync(AppRoles.User))
    {
        await roleManager.CreateAsync(new IdentityRole(AppRoles.User));
    }

    if (!await roleManager.RoleExistsAsync(AppRoles.VipUser))
    {
        await roleManager.CreateAsync(new IdentityRole(AppRoles.VipUser));
    }

    if (!await roleManager.RoleExistsAsync(AppRoles.Administrator))
    {
        await roleManager.CreateAsync(new IdentityRole(AppRoles.Administrator));
    }
}


app.MapControllers();


app.Run();
