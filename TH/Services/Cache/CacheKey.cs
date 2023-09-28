namespace TH.Services.Cache
{
    public class CacheKey
    {
        private readonly string _key;
        private readonly string _unique;
        private readonly string _type;

        public CacheKey(string key)
        {
            _unique = "";
            _type = "";
            _key = key;
        }

        public CacheKey(string unique, string type)
        {
            _unique = unique;
            _type = type;
            _key = _unique + "_" + _type;
        }

        public string Key()
        {
            return _key;
        }
    }
}
