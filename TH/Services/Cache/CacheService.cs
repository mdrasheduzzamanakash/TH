using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using TH.Configurations;

namespace TH.Services.Cache
{
    // TODO
    public class CacheService : ICacheService
    {
        private readonly IMemoryCache _cache;
        
        public CacheService(IMemoryCache cache)
        {
            _cache = cache;
        }

        public void Clear()
        {
            _cache.Dispose();
        }

        public bool ContainsKey(CacheKey key)
        {
            return _cache.TryGetValue(key.Key(), out var _);
        }

        public void Delete(CacheKey key)
        {
            _cache.Remove(key.Key());
        }

        public object Get(CacheKey key)
        {
            return _cache.Get(key.Key()) ?? new object();
        }

        public async Task<object> GetOrSet(CacheKey key, Func<Task<object>> valueFactory, TimeSpan cacheDuration)
        {
            if (_cache.TryGetValue(key.Key(), out var cachedValue))
            {
                return cachedValue ?? new object();
            }

            // Value not found in cache, generate and cache it
            var newValue = await valueFactory();

            var cacheEntryOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = cacheDuration,
            };

            _cache.Set(key.Key(), newValue, cacheEntryOptions);

            return newValue;
        }

        public async Task<object> GetOrSet(CacheKey key, Func<List<object>, Task<object>> valueFactory, TimeSpan cacheDuration, List<object> parameters)
        {
            if (_cache.TryGetValue(key.Key(), out var cachedValue))
            {
                return cachedValue ?? new object();
            }

            // Value not found in cache, generate and cache it
            var newValue = await valueFactory(parameters);

            var cacheEntryOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = cacheDuration,
            };

            _cache.Set(key.Key(), newValue, cacheEntryOptions);

            return newValue;
        }

        public void Set(CacheKey key, object value, TimeSpan cacheDuration)
        {
            var cacheEntryOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = cacheDuration,
            };

            _cache.Set(key.Key(), value, cacheEntryOptions);
        }

    }

}
