namespace TH.Services.Cache
{
    public interface ICacheService
    {
        public object Get(CacheKey key);

        public void Set(CacheKey key, object value, TimeSpan cacheDuration);

        public void Delete(CacheKey key);

        public void Clear();

        public void GetOrSet(CacheKey key, Func<object> valueFactory, TimeSpan cacheDuration);
        public void GetOrSet(CacheKey key, Func<object> valueFactory, TimeSpan cacheDuration, params object[] parameters);
    }
}
