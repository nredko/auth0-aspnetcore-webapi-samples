using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Auth0.AuthenticationApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace UserInfo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // If accessing this API from a browser you'll need to add a CORS policy, see https://docs.microsoft.com/en-us/aspnet/core/security/cors

            string domain = $"https://{Configuration["Auth0:Domain"]}/";
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = domain;
                    options.Audience = Configuration["Auth0:Audience"];

                    options.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            // Grab the raw value of the token, and store it as a claim so we can retrieve it again later in the request pipeline
                            // Have a look at the ValuesController.UserInformation() method to see how to retrieve it and use it to retrieve the
                            // user's information from the /userinfo endpoint
                            if (context.SecurityToken is JwtSecurityToken token)
                            {
                                if (context.Principal.Identity is ClaimsIdentity identity)
                                {
                                    identity.AddClaim(new Claim("access_token", token.RawData));
                                }
                            }

                            return Task.CompletedTask;
                        }
                    };
                });

            services.AddSingleton(x =>
                new AuthenticationApiClient(new Uri($"https://{Configuration["Auth0:Domain"]}/")));
            
            #region Swagger
            
            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
                {
                    Title = "API Documentation",
                    Version = "v1.0",
                    Description = ""
                });
                options.ResolveConflictingActions(x => x.First());
                options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    BearerFormat = "JWT",
                    Flows = new OpenApiOAuthFlows
                    {
                        Implicit  = new OpenApiOAuthFlow
                        {
                            TokenUrl = new Uri($"https://{Configuration["Auth0:Domain"]}/oauth/token"),
                            AuthorizationUrl = new Uri($"https://{Configuration["Auth0:Domain"]}/authorize?audience={Configuration["Auth0:Audience"]}"),
                            Scopes = new Dictionary<string, string>
                            {
                                { "openid", "OpenId" },
                            
                            }
                        }
                    }
                });
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "oauth2" }
                        },
                        new[] { "openid" }
                    }
                });

                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                options.IncludeXmlComments(xmlPath);

            });
            #endregion

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });

            #region Swagger
            
            app.UseSwagger();
            app.UseSwaggerUI(settings =>
            {
                settings.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1.0");
                settings.OAuthClientId(Configuration["Auth0:ClientId"]);
                settings.OAuthClientSecret(Configuration["Auth0:ClientSecret"]);
                settings.OAuthUsePkce();
            });

            #endregion
        }
    }
}
