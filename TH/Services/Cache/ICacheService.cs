namespace TH.Services.Cache
{
    public interface ICacheService
    {
        public bool ContainsKey(CacheKey key);
        public object Get(CacheKey key);

        public void Set(CacheKey key, object value, TimeSpan cacheDuration);

        public void Delete(CacheKey key);

        public void Clear();

        public object GetOrSet(CacheKey key, Func<object> valueFactory, TimeSpan cacheDuration);
        public object GetOrSet(CacheKey key, Func<object, object[]> valueFactory, TimeSpan cacheDuration, params object[] parameters);
    }
}
