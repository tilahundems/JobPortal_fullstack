// using System.Security.Claims;
// using System.Text;
// using JobPortalAPI;
// using Microsoft.AspNetCore.Authentication.JwtBearer;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.IdentityModel.Tokens;
// using Microsoft.OpenApi.Models;

// var builder = WebApplication.CreateBuilder(args);

// // Add services to the container.
// // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
// builder.Services.AddControllers(); // ← Add this line
// builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen();


// builder.Services.AddDbContext<AppDbContext>(options =>
//     options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"))
// );

// // Identity + Roles
// builder.Services
//     .AddIdentity<IdentityUser, IdentityRole>()
//     .AddEntityFrameworkStores<AppDbContext>()
//     .AddDefaultTokenProviders();
//     // (Optional) Relax password rules for testing
// builder.Services.Configure<IdentityOptions>(opt =>
// {
//     opt.Password.RequireDigit = false;
//     opt.Password.RequireLowercase = false;
//     opt.Password.RequireNonAlphanumeric = false;
//     opt.Password.RequireUppercase = false;
//     opt.Password.RequiredLength = 6;
// });


// // JWT Auth
// // builder.Services.AddAuthentication(options =>
// // {
// //     options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
// //     options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
// // }).AddJwtBearer(options =>
// // {
// //     options.TokenValidationParameters = new TokenValidationParameters
// //     {
// //         ValidateIssuer = true,
// //         ValidIssuer = builder.Configuration["Jwt:Issuer"],
// //         ValidateAudience = true,
// //         ValidAudience = builder.Configuration["Jwt:Audience"],
// //         ValidateLifetime = true,
// //         ValidateIssuerSigningKey = true,
// //         IssuerSigningKey = new SymmetricSecurityKey(
// //             Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
// //         ),
// //         // Critical: Map legacy claim types
// //         NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
// //         RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
// //     };
// // });

// // .AddJwtBearer(options =>
// // {
// //     options.TokenValidationParameters = new TokenValidationParameters
// //     {
// //         ValidateIssuer = true,
// //         ValidateAudience = true,
// //         ValidateLifetime = true,
// //         ValidateIssuerSigningKey = true,
// //         ValidIssuer = builder.Configuration["Jwt:Issuer"],
// //         ValidAudience = builder.Configuration["Jwt:Audience"],
// //         IssuerSigningKey = new SymmetricSecurityKey(
// //             Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
// //         ),
// //         //   RoleClaimType = ClaimTypes.Role, // <-- Add this line
// //         //  NameClaimType = ClaimTypes.Name , // Optional: makes [User.Identity.Name] work
// //           NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
// //         RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
// //     };
// // }
// // );


// // builder.Services.AddSwaggerGen(c =>
// // {
// //     c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo { Title = "JobPortalAPI", Version = "v1" });
    
// //     // Add JWT Authentication to Swagger UI
// //     c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
// //     {
// //         Description = "JWT Authorization header using the Bearer scheme",
// //         Name = "Authorization",
// //         In = ParameterLocation.Header,
// //         Type = SecuritySchemeType.Http,
// //         Scheme = "bearer",
// //         BearerFormat = "JWT"
// //     });

// //     c.AddSecurityRequirement(new OpenApiSecurityRequirement
// //     {
// //         {
// //             new OpenApiSecurityScheme
// //             {
// //                 Reference = new OpenApiReference
// //                 {
// //                     Type = ReferenceType.SecurityScheme,
// //                     Id = "Bearer"
// //                 }
// //             },
// //             Array.Empty<string>()
// //         }
// //     });
// // });
// // builder.Services.AddSwaggerGen(c =>
// // {
// //     c.SwaggerDoc("v1", new OpenApiInfo { Title = "JobPortalAPI", Version = "v1" });
    
// //     c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
// //     {
// //         Description = "JWT Authorization",
// //         Name = "Authorization",
// //         In = ParameterLocation.Header,
// //         Type = SecuritySchemeType.ApiKey, // ← Change from Http to ApiKey
// //         Scheme = "Bearer"
// //     });

// //     c.AddSecurityRequirement(new OpenApiSecurityRequirement
// //     {
// //         {
// //             new OpenApiSecurityScheme
// //             {
// //                 Reference = new OpenApiReference
// //                 {
// //                     Type = ReferenceType.SecurityScheme,
// //                     Id = "Bearer"
// //                 }
// //             },
// //             new string[] {}
// //         }
// //     });
// // });
// // builder.Services.AddSwaggerGen(c =>
// // {
// //     c.SwaggerDoc("v1", new OpenApiInfo { Title = "JobPortalAPI", Version = "v1" });
    
// //     c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
// //     {
// //         Type = SecuritySchemeType.Http,
// //         Scheme = "bearer",
// //         BearerFormat = "JWT",
// //         Description = "JWT Authorization header using the Bearer scheme."
// //     });

// //     c.AddSecurityRequirement(new OpenApiSecurityRequirement
// //     {
// //         {
// //             new OpenApiSecurityScheme
// //             {
// //                 Reference = new OpenApiReference
// //                 {
// //                     Type = ReferenceType.SecurityScheme,
// //                     Id = "Bearer"
// //                 }
// //             },
// //             new string[] {}
// //         }
// //     });
// // });


// builder.Services.AddSwaggerGen(c =>
// {
//     c.SwaggerDoc("v1", new OpenApiInfo { Title = "JobPortalAPI", Version = "v1" });

//     // Define the security scheme
//     c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
//     {
//         Name = "Authorization",
//         Type = SecuritySchemeType.Http,
//         Scheme = "bearer",
//         BearerFormat = "JWT",
//         In = ParameterLocation.Header,
//         Description = "Enter JWT token as: Bearer <token>"
//     });

//     // Require the token for all endpoints (or optional)
//     c.AddSecurityRequirement(new OpenApiSecurityRequirement
//     {
//         {
//             new OpenApiSecurityScheme
//             {
//                 Reference = new OpenApiReference
//                 {
//                     Type = ReferenceType.SecurityScheme,
//                     Id = "Bearer"
//                 }
//             },
//             Array.Empty<string>()
//         }
//     });
// });


// var app = builder.Build();

// // Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
//     app.UseSwagger();
//     app.UseSwaggerUI();
// }


// app.UseHttpsRedirection();
// app.UseAuthentication();
// app.UseAuthorization();
// app.MapControllers();

// // Seed roles on startup
// using (var scope = app.Services.CreateScope())
// {
//     var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
//     await SeedRolesAsync(roleManager);
// }
// static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
// {
//     string[] roles = new[] { "Admin", "HR", "Applicant" };
//     foreach (var r in roles)
//         if (!await roleManager.RoleExistsAsync(r))
//             await roleManager.CreateAsync(new IdentityRole(r));
// }




// app.Run();














using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using JobPortalAPI;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// DB Context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"))
);

// Identity
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>(
        options =>
{
    options.SignIn.RequireConfirmedAccount = false; // for dev
}
    )
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

    builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/api/Auth/login";  // redirect if not logged in
    options.AccessDeniedPath = "/api/Jobs";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
});

builder.Services.AddControllersWithViews();

builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Password.RequireUppercase = false;
    opt.Password.RequiredLength = 6;
});



// // JWT Authentication
// builder.Services.AddAuthentication(options =>
// {
//     options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//     options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
// })
// .AddJwtBearer(options =>
// {
//     options.TokenValidationParameters = new TokenValidationParameters
//     {
//         ValidateIssuer = true,
//         ValidateAudience = true,
//         ValidateLifetime = true,
//         ValidateIssuerSigningKey = true,
//         ValidIssuer = builder.Configuration["Jwt:Issuer"],
//         ValidAudience = builder.Configuration["Jwt:Audience"],
//         IssuerSigningKey = new SymmetricSecurityKey(
//             Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
//         ),
//         NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
//         RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
//     };
   

//     options.Events = new JwtBearerEvents
//     {
//         OnAuthenticationFailed = context =>
//         {
//             Console.WriteLine($"Token validation failed XXX: {context.Exception}");
//             return Task.CompletedTask;
//         }
//     };


//     // 🔹 Debugging token issues
//     options.Events = new JwtBearerEvents
//     {
//         OnAuthenticationFailed = context =>
//         {
//             Console.WriteLine("Auth failed: " + context.Exception.Message);
//             return Task.CompletedTask;
//         },
//         OnTokenValidated = context =>
//         {
//             Console.WriteLine("Token validated for user: " + context.Principal?.Identity?.Name);
//             return Task.CompletedTask;
//         }
//     };
// });

// Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JobPortalAPI", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter JWT token as: Bearer <token>"
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
            Array.Empty<string>()
        }
    });
});



builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy =>
        {
            policy.AllowAnyOrigin()   // allow all origins
                  .AllowAnyMethod()   // allow all HTTP methods
                  .AllowAnyHeader();  // allow all headers
        });
});

builder.Services.AddControllers()
    .AddJsonOptions(o =>
    {
        o.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    });

    builder.Services.Configure<FormOptions>(o =>
{
    // Allow reasonably sized resumes (adjust as needed)
    o.MultipartBodyLengthLimit = 10_000_000; // 10MB
});


var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseStaticFiles();
app.UseCors("AllowAll");
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();


// Seed roles
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    await SeedRolesAsync(roleManager);
}

static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
{
    string[] roles = new[] { "Admin", "HR", "Applicant" };
    foreach (var r in roles)
        if (!await roleManager.RoleExistsAsync(r))
            await roleManager.CreateAsync(new IdentityRole(r));
}

app.Run();

