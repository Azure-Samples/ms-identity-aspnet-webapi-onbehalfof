---
services: active-directory
platforms: dotnet
author: TiagoBrenck
level: 400
client: .NET Framework 4.7 Console, JavaScript SPA
service: ASP.NET Web API
endpoint: Microsoft identity platform
---

# Calling a downstream web API from another web API in Microsoft identity platform using the On-Behalf-Of flow

![Build badge](https://identitydivision.visualstudio.com/_apis/public/build/definitions/a7934fdd-dcde-4492-a406-7fad6ac00e17/487/badge)

> This newer sample takes advantage of the Microsoft identity platform.

## About this sample

### Overview

This sample demonstrates a .NET Framework Desktop and JavaScript SPA application calling an ASP.NET Web API, which in turn call the [Microsoft Graph](https://graph.microsoft.com). All these are secured using the Microsoft identity platform.

1. The .Net client desktop application and the JavaScript SPA application both use the [Microsoft Authentication Library (MSAL)](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-overview) to obtain an access token from Azure Active Directory (Azure AD) for the authenticated users:
1. The access token is used as a bearer token to authenticate the user when calling the ASP.NET Web API and the Microsoft Graph API.
1. This sample also uses the name Application ID (client ID) across multiple client applications, a feature supported by the new [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/azure-ad-endpoint-comparison)

> Looking for previous versions of this code sample? Check out the tags on the [releases](../../releases) GitHub page.

The flow is as follows:

1. Sign-in the user in the client application
1. Acquire a token to the Asp.net Web API (`TodoListService`) and call it.
1. The Asp.Net Web API then calls another downstream Web API (The Microsoft Graph).

The TodoListService uses a database to:

- Store the todo list
- Illustrate [token cache serialization](https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/Token-cache-serialization) in a service

   ![Topology](./ReadmeFiles/Topology.png)

### Scenario. How the sample uses MSAL.NET (and MSAL.js)

- `TodoListClient` uses  MSAL.NET to acquire an access token for the user in order to call **TodoListService** Web API. For more information about how to acquire tokens interactively, see [Acquiring tokens interactively Public client application flows](https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/Acquiring-tokens-interactively---Public-client-application-flows).
- `TodoListSPA`, the single page application, uses [MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js) to acquire the access token to call **TodoListService** Web API.
- Then `TodoListService` also uses MSAL.NET  to get an access token to act on behalf of the user to call the Microsoft Graph. For details, see [Service to service calls on behalf of the user](https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/Service-to-service-calls-on-behalf-of-the-user). It then decorates the todolist item entered by the user, with the First name and the Last name of the user. Below is a screenshot of what happens when the user named *automation service account* entered "item1" in the textbox.

  ![Todo list client](./ReadmeFiles/TodoListClient.png)

Both flows use the OAuth 2.0 protocol to obtain the tokens. For more information about how the protocols work in this scenario and other scenarios, see [Authentication Scenarios for Azure AD](http://go.microsoft.com/fwlink/?LinkId=394414).

> Looking for previous versions of this code sample? Check out the tags on the [releases](../../releases) GitHub page.

### Step 1:  Clone or download this repository

From your shell or command line:

```Shell
git clone https://github.com/Azure-Samples/ms-identity-aspnet-webapi-onbehalfof.git
```

or download and extract the repository .zip file.

> Given that the name of the sample is quiet long, and so are the names of the referenced NuGet packages, you might want to clone it in a folder close to the root of your hard drive, to avoid file size limitations on Windows.

### Step 2:  Register the sample application with your Azure Active Directory tenant

There are two projects in this sample. Each needs to be separately registered in your Azure AD tenant. To register these projects, you can:

- either follow the steps [Step 2: Register the sample with your Azure Active Directory tenant](#step-2-register-the-sample-with-your-azure-active-directory-tenant) and [Step 3:  Configure the sample to use your Azure AD tenant](#choose-the-azure-ad-tenant-where-you-want-to-create-your-applications)
- or use PowerShell scripts that:
  - **automatically** creates the Azure AD applications and related objects (passwords, permissions, dependencies) for you
  - modify the Visual Studio projects' configuration files.

If you want to use this automation:

1. On Windows, run PowerShell and navigate to the root of the cloned directory
1. In PowerShell run:

   ```PowerShell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
   ```

1. Run the script to create your Azure AD application and configure the code of the sample application accordingly.
1. In PowerShell run:

   ```PowerShell
   .\AppCreationScripts\Configure.ps1
   ```

   > Other ways of running the scripts are described in [App Creation Scripts](./AppCreationScripts/AppCreationScripts.md)

1. Open the Visual Studio solution and click start to run the code.

If you don't want to use this automation, follow the steps below.

#### Choose the Azure AD tenant where you want to create your applications

As a first step you'll need to:

1. Sign in to the [Azure portal](https://portal.azure.com) using either a work or school account or a personal Microsoft account.
1. If your account is present in more than one Azure AD tenant, select your profile at the top right corner in the menu on top of the page, and then **switch directory**.
   Change your portal session to the desired Azure AD tenant.

#### Register the service app (TodoListService-OBO-sample-v2)

1. Navigate to the Microsoft identity platform for developers [App registrations](https://go.microsoft.com/fwlink/?linkid=2083908) page.
1. Select **New registration**.
1. When the **Register an application page** appears, enter your application's registration information:
   - In the **Name** section, enter a meaningful application name that will be displayed to users of the app, for example `TodoListService-OBO-sample-v2`.
   - Change **Supported account types** to **Accounts in any organizational directory**.
1. Select **Register** to create the application.
1. On the app **Overview** page, find the **Application (client) ID** value and record it for later. You'll need it to configure the Visual Studio configuration file for this project.
1. From the **Certificates & secrets** page, in the **Client secrets** section, choose **New client secret**:

   - Type a key description (of instance `app secret`),
   - Select a key duration of either **In 1 year**, **In 2 years**, or **Never Expires**.
   - When you press the **Add** button, the key value will be displayed, copy, and save the value in a safe location.
   - You'll need this key later to configure the project in Visual Studio. This key value will not be displayed again, nor retrievable by any other means,
     so record it as soon as it is visible from the Azure portal.
1. Select the **API permissions** section
   - Click the **Add a permission** button and then,
   - Ensure that the **Microsoft APIs** tab is selected
   - In the *Commonly used Microsoft APIs* section, click on **Microsoft Graph**
   - In the **Delegated permissions** section, ensure that the right permissions are checked: **User.Read**. Use the search box if necessary.
   - Select the **Add permissions** button

1. Select the **Expose an API** section, and:
   - Select **Add a scope**
   - accept the proposed Application ID URI (api://{clientId}) by selecting **Save and Continue**
   - Enter the following parameters
     - for **Scope name** use `user_impersonation`
     - Keep **Admins and users** for **Who can consent**
     - in **Admin consent display name** type `Access TodoListService-OBO-sample-v2 as a user`
     - in **Admin consent description** type `Allow the application to access TodoListService-OBO-sample-v2 on behalf of the signed-in user.`
     - in **User consent display name** type `Access TodoListService-OBO-sample-v2 as a user`
     - in **User consent description** type `Allow the application to access TodoListService-OBO-sample-v2 on your behalf.`
     - Keep **State** as **Enabled**
     - Select **Add scope**

#### Register the client app (TodoListClient-OBO-sample-v2)

1. Navigate to the Microsoft identity platform for developers [App registrations](https://go.microsoft.com/fwlink/?linkid=2083908) page.
1. Select **New registration**.
1. When the **Register an application page** appears, enter your application's registration information:
   - In the **Name** section, enter a meaningful application name that will be displayed to users of the app, for example `TodoListClient-OBO-sample-v2`.
   - Change **Supported account types** to **Accounts in any organizational directory**.
     > Note that there are more than one redirect URIs. You'll need to add them from the **Authentication** tab later after the app has been created successfully.
1. Select **Register** to create the application.
1. On the app **Overview** page, find the **Application (client) ID** value and record it for later. You'll need it to configure the Visual Studio configuration file for this project.
1. From the app's Overview page, select the **Authentication** section.
   - In the Redirect URIs section, select **Web** in the combo-box and enter the following redirect URIs.
       - `https://login.microsoftonline.com/common/oauth2/nativeclient`
       - `urn:ietf:wg:oauth:2.0:oob`
   - For the `urn:ietf:wg:oauth:2.0:oob` *Redirect URI*, select type `Public client (mobile & desktop)` (this is for the desktop client).
   - In the **Advanced settings** | **Implicit grant** section, check **ID tokens** as this sample requires
     the [Implicit grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow) to be enabled to
     sign-in the user, and call an API.
1. Select **Save**.
1. Select the **API permissions** section
   - Click the **Add a permission** button and then,
   - Ensure that the **My APIs** tab is selected
   - In the list of APIs, select the API `TodoListService-OBO-sample-v2`.
   - In the **Delegated permissions** section, ensure that the right permissions are checked: **Access 'TodoListService-OBO-sample-v2'**. Use the search box if necessary.
   - Select the **Add permissions** button

#### Register the SPA app (TodoListSPA-OBO-sample-v2)

1. Navigate to the Microsoft identity platform for developers [App registrations](https://go.microsoft.com/fwlink/?linkid=2083908) page.
1. Select **New registration**.
1. When the **Register an application page** appears, enter your application's registration information:
   - In the **Name** section, enter a meaningful application name that will be displayed to users of the app, for example `TodoListSPA-OBO-sample-v2`.
   - Change **Supported account types** to **Accounts in any organizational directory**.
     > Note that there are more than one redirect URIs. You'll need to add them from the **Authentication** tab later after the app has been created successfully.
1. Select **Register** to create the application.
1. On the app **Overview** page, find the **Application (client) ID** value and record it for later. You'll need it to configure the Visual Studio configuration file for this project.
1. From the app's Overview page, select the **Authentication** section.
   - In the Redirect URIs section, select **Web** in the combo-box and enter the following redirect URI.
       - `https://localhost:44377`
   - In the **Advanced settings** | **Implicit grant** section, check **Access tokens** and **ID tokens** as this sample requires
     the [Implicit grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow) to be enabled to
     sign-in the user, and call an API.
1. Select **Save**.
1. Select the **API permissions** section
   - Click the **Add a permission** button and then,
   - Ensure that the **My APIs** tab is selected
   - In the list of APIs, select the API `TodoListService-OBO-sample-v2`.
   - In the **Delegated permissions** section, ensure that the right permissions are checked: **Access 'TodoListService-OBO-sample-v2'**. Use the search box if necessary.
   - Select the **Add permissions** button

#### Configure authorized client applications for service (TodoListService-OBO-sample-v2)

For the middle tier web API (`TodoListService-OBO-sample-v2`) to be able to call the downstream web APIs, the user must grant the middle tier permission to do so in the form of consent.
However, since the middle tier has no interactive UI of its own, you need to explicitly bind the client app registration in Azure AD, with the registration for the web API.
This binding merges the consent required by both the client and middle tier into a single dialog, which will be presented to the user by the client.
You can do so by adding the "Client ID" of the client app, to the manifest of the web API in the `knownClientApplications` property. Here's how:

1. In the [Azure portal](https://portal.azure.com), navigate to your `TodoListService-OBO-sample-v2` app registration, and in the *Expose an API* section, click on **Add a client application**.
   Client IDs of the client applications (`TodoListClient-OBO-sample-v2`, `TodoListSPA-OBO-sample-v2`) as elements of the array.
1. Click **Add application**

### Step 3:  Configure the sample to use your Azure AD tenant

In the steps below, "ClientID" is the same as "Application ID" or "AppId".

Open the solution in Visual Studio to configure the projects

#### Configure the service project

> Note: if you used the setup scripts, the changes below will have been applied for you

1. Open the `TodoListService\Web.Config` file
1. Find the app key `ida:Tenant` and replace the existing value with your Azure AD tenant name.
1. Find the app key `ida:Audience` and replace the existing value with the App URI you registered earlier for the `TodoListService-OBO-sample-v2` app.
1. Find the app key `ida:AppKey` and replace the existing value with the key you saved during the creation of the `TodoListService-OBO-sample-v2` app, in the Azure portal.
1. Find the app key `ida:ClientID` and replace the existing value with the application ID (clientId) of the `TodoListService-OBO-sample-v2` application copied from the Azure portal.

#### Configure the client project

> Note: if you used the setup scripts, the changes below will have been applied for you

1. Open the `TodoListClient\App.Config` file
1. Find the app key `ida:Tenant` and replace the existing value with your Azure AD tenant name.
1. Find the app key `ida:ClientId` and replace the existing value with the application ID (clientId) of the `TodoListClient-OBO-sample-v2` application copied from the Azure portal.
1. Find the app key `todo:TodoListScope` and replace the existing value with 'api://{clientId}/.default'.
1. Find the app key `todo:TodoListBaseAddress` and replace the existing value with the base address of the TodoListService-OBO project (by default `https://localhost:44321/`).

#### Configure the client SPA project

> Note: if you used the setup scripts, the changes below will have been applied for you

1. Open the `TodoListSPA\appconfig.js` file
1. Find the app key `authority` and replace the existing value with your authority url, for example `https://login.microsoftonline.com/<your_tenant_name>`.
1. Find the app key `clientId` and replace the existing value with the application ID (clientId) of the `TodoListSPA-OBO-sample-v2` application copied from the Azure portal.
1. Find the app key `redirectUri` and replace the existing value with the base address of the TodoListClient-OBO project (by default `https://localhost:44377/`).
1. Find the app key `resourceId` and replace the existing value with the App URI you registered earlier for the `TodoListSPA-OBO-sample-v2` app.
1. Find the app key `resourceBaseAddress` and replace the existing value with the base address of the TodoListService-OBO project (by default `https://localhost:44321/`).
1. Find the app key `webApiScope` and replace the existing value with "api://{clientId}/.default".

   > While running the SPA app in the browser, take care to allow popups from this app.

### Step 4: Run the sample

Clean the solution, rebuild the solution, and run it. You might want to go into the solution properties and set both projects, or the three projects, as startup projects, with the service project starting first.

Explore the sample by signing in, adding items to the To Do list, Clearing the cache (which removes the user account), and starting again.  The ToDo list service will take the user's access token, received from the client, and use it to get another access token so it can act On Behalf Of the user in the Microsoft Graph API.  This sample caches the user's access token at the To Do list service, so it does not request a new access token on every request. This cache is a database cache.

[Optionally], when you have added a few items with the TodoList Client, login to the todoListSPA with the same credentials as the todoListClient, and observe the id-Token, and the content of the Todo List as stored on the service, but as Json. This will help you understand the information circulating on the network.

## About the code

There are many key points in this sample to make the [**On-Behalf-Of-(OBO) flow**](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow) work properly and in this section we will explain these key points for each project.
Though we have three applications in the solution, you will notice that we only registered two applications in Azure AD. This is because Azure AD now allows multiple types of applications, like in this case a desktop and a javascript SPA application, to share the same app registration in the Azure AD's app registration portal.

### TodoListClient

This project represents the .NET desktop UI part of the flow, where users would sign-in and interact with the Web API (TodoListService). The API that this app calls ((TodoListService)) also requests data from another API (Microsoft Graph) by using an access token obtained for the signed-in user using the **On-Behalf-Of (OBO) flow** . The first key point to pay attention is the `MainWindow` initialization. Here is the code snippet:

```csharp
private readonly IPublicClientApplication _app;

public MainWindow()
{
   InitializeComponent();
   
   _app = PublicClientApplicationBuilder.Create(clientId)
      .WithAuthority(authority)
      .Build();
       
   TokenCacheHelper.EnableSerialization(_app.UserTokenCache);

   GetTodoList();
}
```

Important things to notice:

- We create an `IPublicClientApplication` using **MSAL Build Pattern** passing the `clientId` and `authority` in the builder. This `IPublicClientApplication` will be responsible of acquiring access tokens later in the code.
- `IPublicClientApplication` also has a token cache, that will cache [access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens) and [refresh tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#refresh-the-access-token) for the signed-in user. This is done so that the application can fetch access tokens after they have expired without prompting the user to sign-in again.
- Our `UserTokenCache` implementation uses the local file system for caching. Other popular options for caching tokens are `Database` or `Distributed InMemory cache`.

#### SignIn

Then we have the `SignIn` method, where the login screen is presented to the user and they can provide their credentials.

```csharp
private static readonly string[] Scopes = { "https://<yourTenant>.onmicrosoft.com/TodoListService-OBO/.default" };

private async void SignIn(object sender = null, RoutedEventArgs args = null)
{
   AuthenticationResult result = await _app.AcquireTokenInteractive(Scopes)
      .WithAccount(accounts.FirstOrDefault())
      .WithPrompt(Prompt.SelectAccount)
      .ExecuteAsync()
      .ConfigureAwait(false);
}
```

Important things to notice:

- The scope [`.default`](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#the-default-scope) is a built-in scope for every application that refers to the static list of permissions configured on the application registration. In our scenario here, it enables the user to grant consent for permissions for both the Web API and the downstream API (Microsoft Graph). For example, the permissions for the Web API and the downstream API (Microsoft Graph) are listed below:
   - TodoListService-OBO-sample-v2
     - user_impersonation
   - Microsoft Graph
     - user.read
- When you use the `.default` scope, the end user is prompted for a combined set of permissions that include scopes from both the **TodoListService-OBO** and **Microsoft Graph**.
- We call the [AcquireTokenInteractive](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Acquiring-tokens-interactively) which will present a window to the user to provide their credentials. When it acquires the access token, MSAL also saves this token in its token cache.

#### Add Todo Item

The method to add a new `Todo` is where we consume our **TodoListService-OBO** Web API, that will consume the downstream **Microsoft Graph** using an access token obtained using the **On-Behalf-Of (OBO) flow**.

To check if the user is signed in, we use the method [GetAccountsAsync](https://docs.microsoft.com/en-us/dotnet/api/microsoft.identity.client.clientapplicationbase.getaccountsasync?view=azure-dotnet):

```csharp
var accounts = (await _app.GetAccountsAsync()).ToList();
if (!accounts.Any())
{
   MessageBox.Show("Please sign in first");
   return;
}
```
Now we call the `AcquireTokenSilent` method to get the cached access token we had obtained earlier during our sign-in. With this token, we can then create a HTTP POST request to our Web API attaching it on the header as `Bearer`.

```csharp
AuthenticationResult result = null;
try
{
   result = await _app.AcquireTokenSilent(Scopes, accounts.FirstOrDefault())
      .ExecuteAsync()
      .ConfigureAwait(false);
}
catch (MsalUiRequiredException)
{
   MessageBox.Show("Please re-sign");
}
catch (MsalException ex)
{
   // An unexpected error occurred.
}

HttpClient httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

HttpContent content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("Title", TodoText.Text) });

HttpResponseMessage response = await httpClient.PostAsync(todoListBaseAddress + "/api/todolist", content);

if (response.IsSuccessStatusCode)
{
      TodoText.Text = "";
      GetTodoList();
}
else
{
      MessageBox.Show("An error occurred : " + response.ReasonPhrase);
}
```

Important things to notice:

- After the **Sign-In**, the user token will be cached and it can be acquired again by calling [AcquireTokenSilent](https://docs.microsoft.com/en-us/dotnet/api/microsoft.identity.client.iclientapplicationbase.acquiretokensilentasync?view=azure-dotnet).
- `MsalUiRequiredException` will be thrown if there is no token for that user with the specified scope in the cache, or it got expired. This case requires the user to **Sign-In** again.

### TodoListService

The **TodoListService** is our Web API project that will make a call to the downstream **Microsoft Graph API** using an access token obtained via the [**On-Behalf-Of (OBO) flow**](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow). The client that called **TodoListService**, sends a `Bearer` token on the HTTP header and this token will be used to impersonate the user and acquire another acess token for **Microsoft Graph API**.

The first key point to pay attention in this project is the `Startup` configuration:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
   app.UseWindowsAzureActiveDirectoryBearerAuthentication(
         new WindowsAzureActiveDirectoryBearerAuthenticationOptions
         {
            Tenant = ConfigurationManager.AppSettings["ida:Tenant"],
            TokenValidationParameters = new TokenValidationParameters 
            { 
                SaveSigninToken = true, 
                ValidAudience = ConfigurationManager.AppSettings["ida:Audience"] 
            }
         });
}
```

Important things to notice:

- Notice that we are setting `SaveSigninToken` to `true` on the `TokenValidationParameters`. This is essential to get the `Bearer` token from the HTTP header later, using the identity bootstrap context: `ClaimsPrincipal.Current.Identities.First().BootstrapContext`

#### Call Graph API On Behalf Of User

The logic to call **Microsoft Graph** on behalf of a user is inside the method `CallGraphAPIOnBehalfOfUser`. In this sample, we are getting the user's first name and last name and adding them in the todo's title.

The one thing that you will notice is that we are using a different type of token cache provider in the Web API, which caches tokens in a SQL Server database. The implementation of this caching mechanism is incapsulated in the `MSALPerUserSqlTokenCacheProvider` class.

```csharp
private async Task<UserProfile> CallGraphAPIOnBehalfOfUser()
{
   string[] scopes = { "user.read" };
   UserProfile profile = null;

   try
   {
      var app = ConfidentialClientApplicationBuilder.Create(clientId)
         .WithAuthority(authority)
         .WithClientSecret(appKey)
         .WithRedirectUri(redirectUri)
         .Build();

      MSALPerUserSqlTokenCacheProvider sqlCache = new MSALPerUserSqlTokenCacheProvider(app.UserTokenCache, db, ClaimsPrincipal.Current);

      var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as System.IdentityModel.Tokens.BootstrapContext;

      UserAssertion userAssertion = new UserAssertion(bootstrapContext.Token, "urn:ietf:params:oauth:grant-type:jwt-bearer");

      AuthenticationResult result = await app.AcquireTokenOnBehalfOf(scopes, userAssertion)
         .ExecuteAsync();

      string accessToken = result.AccessToken;
      if (accessToken == null)
      {
         throw new Exception("Access Token could not be acquired.");
      }

      string requestUrl = String.Format(CultureInfo.InvariantCulture, graphUserUrl, HttpUtility.UrlEncode(tenant));
      HttpClient client = new HttpClient();
      HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
      request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
      HttpResponseMessage response = await client.SendAsync(request);

      if (response.IsSuccessStatusCode)
      {
         string responseString = await response.Content.ReadAsStringAsync();
         profile = JsonConvert.DeserializeObject<UserProfile>(responseString);
         return (profile);
      }

      throw new Exception("An unexpected error occurred calling the Graph API.");
   }
   catch (Exception ex)
   {
      throw ex;
   }
}
```

Important things to notice:

- We are using the scope `user.read` to get the user's profile on **Microsoft Graph**.
- The `ConfidentialClientApplication` is built using the **Build pattern** introduced in MSAL v3.x, passing the `clientId`, `authority`, `appKey` and `redirectUri` to the builder. All of these values are related to the **TodoListService**. We don't use anything related to the **TodoListClient** application here.
- We hook the `ConfidentialClientApplication` `UserTokenCache` on our `MSALPerUserSqlTokenCacheProvider`, so we can store the cache on the database. Other alternatives for cache storage could be `InMemory` or `Session`.
- We instantiate a `UserAssertion` using the `Bearer` token sent by the client and `urn:ietf:params:oauth:grant-type:jwt-bearer` as assertion type ([read more here](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow)). This class represents the credential of the user being impersonated.
- The method `AcquireTokenOnBehalfOf` will try to get a token for the impersonated user. If all the validations pass and the impersonated user have consented the requested scope (`user.read` on our sample), an access token will be returned and be used on **Microsoft Graph** request **on behalf on the user**.

### TodoListSPA

The project **TodoListSPA** has the same role as **TodoListClient**. It represents the UI part of the flow, where users can interact with and consumes **TodoListService** Web API. This project is using [MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js) and uses the method `loginPopup` to establish a user context.

The first key point in this project is the `UserAgentApplication` instantiation. Here is the code:

```javascript
var config = {
    popUp: true,
    webApiScope: "https://<yourTenant>/TodoListService-OBO/.default",
    auth: {
       authority: "https://login.microsoftonline.com/<yourTenant>",
       clientId: "<TodoListSPA_ClientId>",
       redirectUri: "http://localhost:16969/",
    },
    cache: {
       cacheLocation: "localStorage",
       storeAuthStateInCookie: true
    }
}

const clientApplication = new Msal.UserAgentApplication(config);
```

Important things to notice:

- We are using the [ConfigurationOptions](https://github.com/AzureAD/microsoft-authentication-library-for-js/wiki/MSAL.js-1.0.0-api-release#configuration-options) introduced on [MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js) to initialize the client application.
- The `config` is found at `appconfig.js` file.
- We are using `localStorage` to store the cache. The other option would be `sessionStorage`.

#### SignIn

The entry point in this project, is the method `displayTodoList()`, triggered when the user clicks on the **Display the todo list** button. This method checks if the user is logged and prompts the login screen in case they are not. The `config` is found at `appconfig.js` file.

```javascript
const loginRequest = {
    scopes: [config.webApiScope],
    prompt: "select_account",
}

function displayTodoList() {
    var account = clientApplication.getAccount();

    if (account) {
       onLogin(null, account);
    }
    else {
       clientApplication.loginPopup(loginRequest).then(function (loginResponse) {
          if (loginResponse.account) {
             onLogin(null, loginResponse.account);
          }
       });
    }
}
```

Important things to notice:

- To find out if the user is logged in, we use the method `getAccount()` which returns an object [Account](https://htmlpreview.github.io/?https://raw.githubusercontent.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-core/docs/classes/_useragentapplication_.useragentapplication.html#getaccount) when the user is logged in.
- To prompt the login screen, we call the method `loginPopup()` passing the `loginRequest` object for configuration. The method returns an [AuthResponse promise](https://github.com/AzureAD/microsoft-authentication-library-for-js/wiki/MSAL.js-1.0.0-api-release#configuration-options). Another option to prompt it is using `loginRedirect()`, however this method requires a slightly different configuration. You can read more about these two methods on [MSAL.js documentation](https://github.com/AzureAD/microsoft-authentication-library-for-js).

#### Calling TodoListService WebAPI

Once the user have logged in, they can call our **TodoListService** Web API sending the `Bearer` token on the HTTP header. Here is the code:

```javascript
const accessTokenRequest = {
    scopes: [config.webApiScope]
}

function acquireAnAccessTokenAndCallTheProtectedService() {
    clientApplication.acquireTokenSilent(accessTokenRequest)
       .then(response => {
          callServiceWithToken(response.accessToken, webApiConfig.resourceBaseAddress + "api/todolist");
       })
       .catch(err => {
          if (err.name === "InteractionRequiredAuthError") {
             clientApplication.acquireTokenPopup(accessTokenRequest).then(
                function (response) {
                   callServiceWithToken(response.accessToken, webApiConfig.resourceBaseAddress + "api/todolist");
                }).catch(function (error) {
                   console.log(error);
                });
          } else {
             showError("acquireToken", err.errorMessage);
          }
       });
}

function callServiceWithToken(token, endpoint) {
    var headers = new Headers();
    var bearer = "Bearer " + token;
    headers.append("Authorization", bearer);
    var options = {
       method: "GET",
       headers: headers
    };

    // Note that fetch API is not available in all browsers
    fetch(endpoint, options)
       .then(function (response) {
          var contentType = response.headers.get("content-type");
          if (response.status === 200 && contentType && contentType.indexOf("application/json") !== -1) {
             // Case where we got the content from the API (as JSon)
             response.json()
                .then(function (data) {
                   // Display response in the page
                })
                .catch(function (error) {
                   showError(endpoint, error);
                });
          } else if (response.status === 403 && contentType && contentType.indexOf("text/plain; charset=utf-8") !== -1) {
             response.text()
                .then(function (data) {
                   var claims = data;
                   clientApplication.acquireTokenPopup(claims).then(function (response) {
                      onAccessToken(null, response.accessToken, null);
                   }).catch(function (error) {
                      console.log(error);
                   });
                })
                .catch(function (error) {
                   showError(endpoint, error);
                });
          } else {
             response.text()
                .then(function (data) {
                   // Display response in the page
                   showError(endpoint, data);
                })
                .catch(function (error) {
                   showError(endpoint, error);
                });
          }
       })
       .catch(function (error) {
          showError(endpoint, error);
       });
}
```

## How to deploy this sample to Azure

This project has two WebApp / Web API projects. To deploy them to Azure Web Sites, you'll need, for each one, to:

- create an Azure Web Site
- publish the Web App / Web APIs to the web site, and
- update its client(s) to call the web site instead of IIS Express.

### Create and publish the `TodoListService-OBO-sample-v2` to an Azure Web Site

1. Sign in to the [Azure portal](https://portal.azure.com).
1. Click `Create a resource` in the top left-hand corner, select **Web** --> **Web App**, and give your web site a name, for example, `TodoListService-OBO-sample-v2-contoso.azurewebsites.net`.
1. Thereafter select the `Subscription`, `Resource Group`, `App service plan and Location`. `OS` will be **Windows** and `Publish` will be **Code**.
1. Click `Create` and wait for the App Service to be created.
1. Once you get the `Deployment succeeded` notification, then click on `Go to resource` to navigate to the newly created App service.
1. The following steps provide instructions to create a Sql database that the sample needs. If you already have a Sql Server and database present and a connection string available, skip the steps till we ask you to provide the connections string in the `Application Settings`.
1. Click `Create a resource` in the top left-hand corner again, select **Databases** --> **SQL Database**, to create a new database. Follow the `Quickstart tutorial` if needed.
1. You can name the Sql server and database whatever you want to.
1. Select or create a database server, and enter server login credentials. Carefully note down the username and password for the Sql server as you'll need it when constructing your Sql conenction string later.
1. Wait for the `Deployment succeeded` notification, then click on `Go to resource` to navigate to the newly created database's manage screen.
1. Click on **Connection Strings** on left menu and copy the **ADO.NET (SQL authentication)** connection string. Populate  **User ID={your_username};Password={your_password};** with values your provided during database creation.Copy this connection string.
1. Once the web site is created, locate it it in the **Dashboard** and click it to open **App Services** **Overview** screen.
1. Click on **Configuration** in the left menu of the App service and add the copied Sql connection string in the **Connection strings** section as `DefaultConnection`.
1. Choose `SQLAzure` in the **Type** dropdown. **Save** the setting.
1. From the **Overview** tab of the App Service, download the publish profile by clicking the **Get publish profile** link and save it.  Other deployment mechanisms, such as from source control, can also be used.
1. Switch to Visual Studio and go to the TodoListService-OBO-sample-v2 project.  Right click on the project in the Solution Explorer and select **Publish**.  Click **Import Profile** on the bottom bar, and import the publish profile that you downloaded earlier.
1. Click on **Configure** and in the `Connection tab`, update the Destination URL so that it is a `https` in the home page url, for example [https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net](https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net). Click **Next**.
1. On the Settings tab, make sure `Enable Organizational Authentication` is NOT selected.
1. Under **Databases**, select the connection that you created on **Azure Portal** (if it does not show on the dropdown, click on the button and add it).
1. Make sure `Use this connection string at runtime` and `Execute Code First Migrations` are **checked**.
1. Click **Save**. Click on **Publish** on the main screen.
1. Visual Studio will publish the project and automatically open a browser to the URL of the project. Give it a minute for the migrations to run. If you see the default web page of the project, the publication was successful.

### Update the Active Directory tenant application registration for `TodoListService-OBO-sample-v2`

1. Navigate back to to the [Azure portal](https://portal.azure.com).
In the left-hand navigation pane, select the **Azure Active Directory** service, and then select **App registrations (Preview)**.
1. In the resultant screen, select the `TodoListService-OBO-sample-v2` application.
1. From the *Branding* menu, update the **Home page URL**, to the address of your service, for example [https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net](https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net). Save the configuration.
1. Add the same URL in the list of values of the *Authentication -> Redirect URIs* menu. If you have multiple redirect urls, make sure that there a new entry using the App service's Uri for each redirect url.

### Update the `TodoListClient-OBO-sample-v2` to call the `TodoListService-OBO-sample-v2` Running in Azure Web Sites

1. In Visual Studio, go to the `TodoListClient-OBO-sample-v2` project.
2. Open `TodoListClient\App.Config`.  Only one change is needed - update the `todo:TodoListBaseAddress` key value to be the address of the website you published,
   for example, [https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net](https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net).
3. Run the client! If you are trying multiple different client types (for example, .Net, Windows Store, Android, iOS) you can have them all call this one published web API.

### Update the `TodoListSPA-OBO-sample-v2` to call the `TodoListService-OBO-sample-v2` Running in Azure Web Sites

1. In Visual Studio, go to the `TodoListSPA-OBO-sample-v2` project.
2. Open `TodoListSPA\appconfig.js`.  Only one change is needed - update the `todo:TodoListBaseAddress` key value to be the address of the website you published,
   for example, [https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net](https://TodoListService-OBO-sample-v2-contoso.azurewebsites.net).
3. Run the client! If you are trying multiple different client types (for example, .Net, Windows Store, Android, iOS) you can have them all call this one published web API.

### Create and publish the `TodoListSPA-OBO-sample-v2` to an Azure Web Site

1. Sign in to the [Azure portal](https://portal.azure.com).
1. Click `Create a resource` in the top left-hand corner, select **Web** --> **Web App**, and give your web site a name, for example, `TodoListSPA-OBO-sample-v2-contoso.azurewebsites.net`.
1. Thereafter select the `Subscription`, `Resource Group`, `App service plan and Location`. `OS` will be **Windows** and `Publish` will be **Code**.
1. Click `Create` and wait for the App Service to be created.
1. Once you get the `Deployment succeeded` notification, then click on `Go to resource` to navigate to the newly created App service.
1. Once the web site is created, locate it it in the **Dashboard** and click it to open **App Services** **Overview** screen.
1. From the **Overview** tab of the App Service, download the publish profile by clicking the **Get publish profile** link and save it.  Other deployment mechanisms, such as from source control, can also be used.
1. Switch to Visual Studio and go to the TodoListSPA-OBO-sample-v2 project.  Right click on the project in the Solution Explorer and select **Publish**.  Click **Import Profile** on the bottom bar, and import the publish profile that you downloaded earlier.
1. Click on **Configure** and in the `Connection tab`, update the Destination URL so that it is a `https` in the home page url, for example [https://TodoListSPA-OBO-sample-v2-contoso.azurewebsites.net](https://TodoListSPA-OBO-sample-v2-contoso.azurewebsites.net). Click **Next**.
1. On the Settings tab, make sure `Enable Organizational Authentication` is NOT selected.  Click **Save**. Click on **Publish** on the main screen.
1. Visual Studio will publish the project and automatically open a browser to the URL of the project.  If you see the default web page of the project, the publication was successful.

### Update the Active Directory tenant application registration for `TodoListSPA-OBO-sample-v2`

1. Navigate back to to the [Azure portal](https://portal.azure.com).
In the left-hand navigation pane, select the **Azure Active Directory** service, and then select **App registrations (Preview)**.
1. In the resultant screen, select the `TodoListSPA-OBO-sample-v2` application.
1. From the *Branding* menu, update the **Home page URL**, to the address of your service, for example [https://TodoListSPA-OBO-sample-v2-contoso.azurewebsites.net](https://TodoListSPA-OBO-sample-v2-contoso.azurewebsites.net). Save the configuration.
1. Add the same URL in the list of values of the *Authentication -> Redirect URIs* menu. If you have multiple redirect urls, make sure that there a new entry using the App service's Uri for each redirect url.

## How To Recreate This Sample

First, in Visual Studio 2017 create an empty solution to host the  projects. Then, follow these steps to create each project.

### Creating the TodoListService Project

1. In Visual Studio 2017, create a new `Visual C#` `ASP.NET Web Application (.NET Framework)` project. In the next screen, choose the `Web API` project template.  And while on this screen, click the Change Authentication button, select 'Work or School Accounts', 'Cloud - Single Organization', enter the name of your Azure AD tenant.  You will be prompted to sign in to your Azure AD tenant.  NOTE:  You must sign in with a user that is in the tenant; you cannot, during this step, sign in with a Microsoft account.
1. Add the Microsoft Authentication Library (MSAL) NuGet, Microsoft.Identity.Client, EntityFramework, and Microsoft.AspNet.WebApi.Cors to the project.
1. Add reference of the `System.IdentityModel` assembly in the project.
1. In the `Models` folder, add a new class called `TodoItem.cs`.  Copy the implementation of TodoItem from this sample into the class.
1. In the `Models` folder, add a new class called `UserProfile.cs`.  Copy the implementation of UserProfile from this sample into the class.
1. Create a new folder named `DAL`. In the `DAL` folder, add a new class called `TodoListServiceContext.cs`.  Copy the implementation of TodoListServiceContext from this sample into the class.
1. Create a new folder named `Utils`. In the `Utils` folder, add three new classes (`ClaimConstants.cs`, `ClaimsPrincipalExtensions.cs` and `MSALPerUserSqlTokenCacheProvider`) and copy their implementations from this sample.
1. Add a new, empty, Web API 2 Controller called `TodoListController`.
1. Copy the implementation of the TodoListController from this sample into the controller.  Don't forget to add the `[Authorize]` attribute to the class.
1. In `web.config` make sure that the key `ida:AADInstance`, `ida:Tenant`, `ida:ClientID`, and `ida:AppKey` exist, and are populated.  For the global Azure cloud, the value of `ida:AADInstance` is `https://login.onmicrosoft.com/{0}`.
1. In `web.config`, in `<appSettings>`, create keys for `ida:GraphUserUrl` and set the its value to `https://graph.microsoft.com/v1.0/me/`.

### Creating the TodoListClient Project

1. In the solution, create a new Windows --> Windows Classic Desktop -> WPF App(.NET Framework)  called TodoListClient.
1. Add the  Microsoft Authentication Library (MSAL) NuGet, Microsoft.Identity.Client to the project.
1. Add  assembly references to `System.Net.Http`, `System.Web.Extensions`, and `System.Configuration`.
1. Add a new class to the project called `TodoItem.cs`.  Copy the code from the sample project file of the same name into this class, completely replacing the code in the file in the new project.
1. Add a new class to the project called `FileCache.cs`.  Copy the code from the sample project file of the same name into this class, completely replacing the code in the file in the new project.
1. Copy the markup from `MainWindow.xaml' in the sample project into the file of the same name in the new project, completely replacing the markup in the file in the new project.
1. Copy the code from `MainWindow.xaml.cs` in the sample project into the file of the same name in the new project, completely replacing the code in the file in the new project.
1. In `app.config` create keys for `ida:AADInstance`, `ida:Tenant`, `ida:ClientId`, `ida:RedirectUri`, `todo:TodoListScope`, and `todo:TodoListBaseAddress` and set them accordingly.  For the global Azure cloud, the value of `ida:AADInstance` is `https://login.onmicrosoft.com/{0}`.

Finally, in the properties of the solution itself, set both projects as startup projects.

## Community Help and Support

Use [Stack Overflow](http://stackoverflow.com/questions/tagged/msal) to get support from the community.
Ask your questions on Stack Overflow first and browse existing issues to see if someone has asked your question before.
Make sure that your questions or comments are tagged with [`msal` `dotnet`].

If you find a bug in the sample, please raise the issue on [GitHub Issues](../../issues).

To provide a recommendation, visit the following [User Voice page](https://feedback.azure.com/forums/169401-azure-active-directory).

## Contributing

If you'd like to contribute to this sample, see [CONTRIBUTING.MD](/CONTRIBUTING.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information, see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Other samples and documentation

- Other samples for Microsoft identity platform are available from [https://aka.ms/aaddevsamplesv2](https://aka.ms/aaddevsamplesv2)
- [Microsoft identity platform and Implicit grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow)
- [Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow)
- The conceptual documentation for MSAL.NET is available from [https://aka.ms/msalnet](https://aka.ms/msalnet)
- the documentation for Microsoft identity platform is available from [https://aka.ms/aadv2](https://aka.ms/aadv2)
- [Why update to Microsoft identity platform (v2.0)?](https://docs.microsoft.com/en-us/azure/active-directory/develop/azure-ad-endpoint-comparison)
For more information about how OAuth 2.0 protocols work in this scenario and other scenarios, see [Authentication Scenarios for Azure AD](http://go.microsoft.com/fwlink/?LinkId=394414).
