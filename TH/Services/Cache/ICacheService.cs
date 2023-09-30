namespace TH.Services.Cache
{
    public interface ICacheService
    {
        bool ContainsKey(CacheKey key);
        object Get(CacheKey key);

        void Set(CacheKey key, object value, TimeSpan cacheDuration);

        void Delete(CacheKey key);

        void Clear();

        Task<object> GetOrSet(CacheKey key, Func<Task<object>> valueFactory, TimeSpan cacheDuration);
        Task<object> GetOrSet(CacheKey key, Func<List<object>, Task<object>> valueFactory, TimeSpan cacheDuration, List<object> parameters);
    }
}
