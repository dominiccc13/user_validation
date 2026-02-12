using c_;
using DotNetEnv;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Diagnostics;

DotNetEnv.Env.Load();
static async Task Execute(string recipient, string token)
{
    var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
    var client = new SendGridClient(apiKey);
    var from = new EmailAddress("dominicstefani98@gmail.com", "PWM");
    var subject = "PWM Email Verification";
    var to = new EmailAddress(recipient, "Recipient");
    var plainTextContent = $"Click here to verify: http://localhost:7023/verify?username={recipient}&token={token}";
    var htmlContent = $"<strong>Click here to verify:</strong> <a href='http://localhost:7023/verify?username={recipient}&token={token}'>Verify Email</a>";
    var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
    var response = await client.SendEmailAsync(msg);
}

var db = new Database("DataSource = database.db");
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", async (HttpContext context) =>
{
    if (context.Request.Cookies.ContainsKey(".MyAuthToken"))
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/index.html"), "text/html");
    }
    return Results.File(Path.Combine(app.Environment.ContentRootPath, "wwwroot/login.html"), "text/html");
});
app.MapGet("/js/index_script.js", async (HttpContext context) =>
{
    if (context.Request.Cookies.ContainsKey(".MyAuthToken"))
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/index_script.js"), "text/javascript");
    } else
    {
        return Results.Unauthorized();
    }
});
app.MapPost("/accounts", async (HttpContext context) =>
{
    List<AccountEntry> accounts;
    
    var form = await context.Request.ReadFormAsync();
    string username = form["username"];

    if (!string.IsNullOrEmpty(username))
    {
        accounts = db.getAccountInfo(username);

        return Results.Ok(accounts);
    }

    return Results.BadRequest("Username missing");
});
app.MapPost("/login", async (HttpContext context) =>
{
    if (context.Request.Cookies.ContainsKey(".MyAuthToken"))
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/index.html"), "text/html");
    }

    var form = await context.Request.ReadFormAsync();
    string username = form["username"];
    string password = form["password"];

    var result = db.Login(username, password);
    if (result == "Success")
    {
        context.Response.Cookies.Append(".MyAuthToken", username, new CookieOptions
        {
            HttpOnly = true, 
            Secure = true,   
            SameSite = SameSiteMode.Strict 
        });
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/index.html"), "text/html");
    }
    else if (result == "Invalid credentials")
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "wwwroot/login.html"), "text/html");
    }
    else
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/verify.html"), "text/html");
    }
});
app.MapPost("/register", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string username = form["username"];
    string password = form["password"];

    var token = db.Register(username, password);
    if (token != "failed")
    {
        await Execute(username, token);
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/verify.html"), "text/html");
    }
    else
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/register.html"), "text/html");
    }
});
app.MapGet("/verify", async (HttpContext context) =>
{
    string username = context.Request.Query["username"];
    string resend = context.Request.Query["resend"];
    string token;
    if (resend == "true")
    {
        token = db.GetToken(username);
        await Execute(username, token);
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/verify.html"), "text/html");
    } else
    {
        token = context.Request.Query["token"];
    }

    if (db.Verify(username, token))
    {
        context.Response.Cookies.Append(".MyAuthToken", username, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        });
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/index.html"), "text/html");
    } else
    {
        return Results.File(Path.Combine(app.Environment.ContentRootPath, "Private/verify.html"), "text/html");
    }
});
app.MapGet("/get_salt", async (HttpContext context) =>
{
    string username = context.Request.Query["username"];

});
app.Run();