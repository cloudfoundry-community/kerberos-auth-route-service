namespace RouteServiceAuth
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public interface IWhitelist
    {
        bool IsWhitelisted(HttpRequest request);
    }

    public class Whitelist : IWhitelist
    {
        const string BaseAddress = "http://localhost";

        public List<Uri> Entries { get;} = new List<Uri>();
        private readonly ILogger _logger;

        public Whitelist(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory?.CreateLogger<Whitelist>();
        }

        public Uri CreateEntry(Uri source)
        {
            return CreateEntry(source.AbsolutePath);
        }

        public Uri CreateEntry(string absolutePath)
        {
            var uri = new Uri($"{BaseAddress}{absolutePath}");
            return uri;
        }

        public bool IsWhitelisted(HttpRequest request)
        {
            _logger?.LogDebug($"Whitelist.IsWhitelisted: {request.Path}");
            if(request.Headers.TryGetForwardAddress(out var forwardTo))
            {
                if(Uri.TryCreate(forwardTo, UriKind.Absolute, out var forwardUri))
                {
                    _logger.LogTrace($"Checking whitelist on behalf of {forwardUri}");
                    forwardUri = CreateEntry(forwardUri);
                    if(Entries.Any(e=>e.IsBaseOf(forwardUri)))
                    {
                        _logger.LogTrace($"{forwardUri}:true");
                        return true;
                    }
                    _logger.LogTrace($"{forwardUri}:false");
                    return false;
                }
                else
                {
                    _logger.LogWarning("Unexpected content passed as header value; expected a valid Uri; enable tracing to view untrusted header values.");
                    _logger.LogTrace($"Unexpected content passed as header value; expected a valid Uri; value={forwardTo};");

                    throw new Exception("Could not construct valid Uri from forward address");
                }
            }
            return false;
        }
    }
}