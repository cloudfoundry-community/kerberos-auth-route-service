using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;

namespace RouteServiceAuth
{
    public static class Extensions
    {
        public static IServiceCollection AddWhitelist(this IServiceCollection services, IConfiguration configuration, ILoggerFactory loggerFactory)
        {
            var whitelist = new Whitelist(loggerFactory);
            var section = configuration.GetSection("whitelist");
            var scope = "whitelist =====>";
            var logger = loggerFactory.CreateLogger("Whitelist Configurator");
            logger.LogDebug(scope);
            foreach(var child in section.GetChildren())
            {
                var entry = whitelist.CreateEntry(child.Value);
                whitelist.Entries.Add(entry);
                logger.LogDebug($"{scope} Added {entry}");
            }
            services.AddSingleton<IWhitelist>(whitelist);
            return services;
        }

        public static bool TryGetForwardAddress(this IHeaderDictionary headers, out string forwardAddress)
        {
            forwardAddress = null;
            if(headers.TryGetValue(Constants.X_CF_Forwarded_Url, out var values))
            {
                forwardAddress = values.ToString();
            }
            return null != forwardAddress;
        }
    }
}