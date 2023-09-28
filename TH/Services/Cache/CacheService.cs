using Microsoft.Extensions.Caching.Memory;

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
            throw new NotImplementedException();
        }

        public void Delete(CacheKey key)
        {
            throw new NotImplementedException();
        }

        public object Get(CacheKey key)
        {
            throw new NotImplementedException();
        }

        public void GetOrSet(CacheKey key, Func<object> valueFactory, TimeSpan cacheDuration)
        {
            throw new NotImplementedException();
        }

        public void GetOrSet(CacheKey key, Func<object> valueFactory, TimeSpan cacheDuration, params object[] parameters)
        {
            throw new NotImplementedException();
        }

        public void Set(CacheKey key, object value, TimeSpan cacheDuration)
        {
            throw new NotImplementedException();
        }
    }

}
