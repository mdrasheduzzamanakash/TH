namespace TH.Services
{
    public interface IGenericService<T> where T : class
    {
        Task<IEnumerable<T>> GetAllAsync();
        Task<T?> GetByIdAsync(string id);
        Task<T?> InsertAsync(T entity);
        Task<T?> UpdateAsync(T entity, string id);
        Task<bool> DeleteAsync(string id);

    }
}
