using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Data.Sqlite;
using System.Data.SqlTypes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace c_
{
    public class AccountEntry
    {
        public string Account { get; set; }
        public string EncPassword { get; set; }
        public string Iv { get; set; }
    }
    public class Database
    {
        private readonly string _connectionString;
        public Database(string connectionString)
        {
            _connectionString = connectionString;
        }
        public List<AccountEntry> getAccountInfo(string username)
        {
            var accounts = new List<AccountEntry>();

            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT account, encPassword, iv FROM accounts WHERE username = @u;";
                command.Parameters.AddWithValue("@u", username);

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        accounts.Add(new AccountEntry
                        {
                            Account = reader.GetString(0),
                            EncPassword = reader.GetString(1),
                            Iv = reader.GetString(2)
                        });
                    }
                }
                return accounts;
            }
        }
        public static string GenerateToken()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, 16).Select(s => s[RandomNumberGenerator.GetInt32(s.Length)]).ToArray());
        }
        public string Register(string username, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
            string hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                var token = GenerateToken();

                var register = connection.CreateCommand();
                register.CommandText = "INSERT INTO users (username, password, salt, verified, token) SELECT @u, @p, @s, 0, @t WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = @u);";
                register.Parameters.AddWithValue("@u", username);
                register.Parameters.AddWithValue("@p", hashedPassword);
                register.Parameters.AddWithValue("@s", Convert.ToBase64String(salt));
                register.Parameters.AddWithValue("@t", token);

                try
                {
                    int rowsAffected = register.ExecuteNonQuery();
                    if (rowsAffected > 0)
                    {
                        return token;
                    } else
                    {
                        return "failed";
                    }
                }
                catch (Exception)
                {
                    return "failed";
                }
            }
        }
        public string GetToken(string username)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT token FROM users WHERE username = @u;";
                command.Parameters.AddWithValue("@u", username);
                var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    var token = reader.GetString(0);
                    return token;
                } else
                {
                    return "failed";
                }
            }
        }
        public string Login(string username, string password)
        {
            byte[] saltBytes;
            string storedHash;
            string storedSalt;

            var connection = new SqliteConnection(_connectionString);
            using (connection)
            {
                connection.Open();
                var getCols = connection.CreateCommand();
                getCols.CommandText = "SELECT password, salt, verified FROM users WHERE username = @u";
                getCols.Parameters.AddWithValue("@u", username);

                using var reader = getCols.ExecuteReader();
                if (reader.Read())
                {
                    storedHash = reader.GetString(0);
                    storedSalt = reader.GetString(1);
                    int verified = reader.GetInt16(2);
                    //int verified = 1;
                    saltBytes = Convert.FromBase64String(storedSalt);

                    var passwordHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                        password: password,
                        salt: saltBytes,
                        prf: KeyDerivationPrf.HMACSHA256,
                        iterationCount: 100000,
                        numBytesRequested: 256 / 8));

                    if (storedHash == passwordHash && verified == 1)
                    {
                        return "Success";
                    }
                    else if (storedHash == passwordHash && verified == 0)
                    {
                        return "Not verified";
                    }
                    else
                    {
                        return "Invalid credentials";
                    }
                }
                else { return "Invalid credentials"; }
            }
        }
        public bool Verify(string username, string token)
        {
            string dbUser;
            string dbToken;

            var connection = new SqliteConnection(_connectionString);
            using (connection)
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT username, token FROM users WHERE username = @u";
                command.Parameters.AddWithValue("@u", username);

                var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    dbUser = reader.GetString(0);
                    dbToken = reader.GetString(1);
                    if (username == dbUser && token == dbToken)
                    {
                        var verify = connection.CreateCommand();
                        verify.CommandText = "UPDATE users SET verified = 1 WHERE username = @u;";
                        verify.Parameters.AddWithValue("@u", username);
                        verify.ExecuteNonQuery();

                        return true;
                    } else { return false; }
                }
                else { return false; }
            }
        }
        //public bool AlterTable()
        //{
        //    using (var connection = new SqliteConnection(_connectionString))
        //    {
        //        connection.Open();
        //        var tableCmd = connection.CreateCommand();
        //        tableCmd.CommandText = "ALTER TABLE users ADD COLUMN verified INT;";

        //        try
        //        {
        //            tableCmd.ExecuteNonQuery();
        //            return true;
        //        } catch (Exception)
        //        {
        //            return false;
        //        }
        //    }
        //}
        //public bool Create()
        //{
        //    var connectionStringBuilder = new SqliteConnectionStringBuilder { DataSource = "database.db" };
        //    using (var connection = new SqliteConnection(connectionStringBuilder.ConnectionString))
        //    {
        //        connection.Open();

        //        var tableCmd = connection.CreateCommand();
        //        tableCmd.CommandText =
        //        @"
        //            CREATE TABLE IF NOT EXISTS users (
        //                id INTEGER PRIMARY KEY AUTOINCREMENT,
        //                username TEXT NOT Null,
        //                password TEXT NOT Null
        //            );

        //            INSERT INTO users (username, password)
        //            SELECT 'admin', 'password123'
        //            WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');
        //        ";
        //        try
        //        {
        //            tableCmd.ExecuteNonQuery();
        //            return true;
        //        } 
        //        catch (Exception)
        //        {
        //            return false;
        //        }
        //    }
        //}
    }
}
