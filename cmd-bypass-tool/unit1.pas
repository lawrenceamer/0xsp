unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes,windows, SysUtils, process, Forms, Controls, Graphics, Dialogs, StdCtrls;


const
  buf_size = 2024;
type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    Edit1: TEdit;
    Label1: TLabel;
    Memo1: TMemo;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private

  public

  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

{ TForm1 }
function SystemFolder: string;
begin
 SetLength(Result, Windows.MAX_PATH);
 SetLength(
   Result, Windows.GetSystemDirectory(PChar(Result), Windows.MAX_PATH)
 );
end;
function runit(cmd:string;arg:string):string;
var
    process : Tprocess;
    output: string;
    list : Tstringlist;
    OutputStream : TStream;
    BytesRead    : longint;
    Buffer       : array[1..BUF_SIZE] of byte;

 begin

   process := Tprocess.Create(nil);
   OutputStream := TMemoryStream.Create;    // we are going to store outputs as memory stream .
   process.Executable:=systemfolder+'\cmd.exe';
   process.CommandLine:=cmd; // we can add value of arg into params to control plugin output
   try
   process.Options:= [poUsePipes];
   process.Execute;
    repeat
    // Get the new data from the process to a maximum of the buffer size that was allocated.
    // Note that all read(...) calls will block except for the last one, which returns 0 (zero).
      BytesRead := Process.Output.Read(Buffer, BUF_SIZE);
      OutputStream.Write(Buffer, BytesRead)
    until BytesRead = 0;    //stop if no more data is being recieved

  outputstream.Position:=0;
  form1.Memo1.Lines.LoadFromStream(outputstream);   // add output into Memo component


   finally
   process.Free;
   end;
end;
procedure TForm1.Button1Click(Sender: TObject);
var
cmd_s:string;
begin
  cmd_s := 'cmd.exe /c ';
  runit(cmd_s+edit1.Text,'');
end;

procedure TForm1.FormCreate(Sender: TObject);
begin

end;

end.

