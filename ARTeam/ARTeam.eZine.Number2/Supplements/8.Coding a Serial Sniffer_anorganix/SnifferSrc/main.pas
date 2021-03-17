unit main;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, Clipbrd;

type
  TfrmMain = class(TForm)
    gbLog: TGroupBox;
    lblLog: TLabel;
    btnClose: TButton;
    btnSniff: TButton;
    lblAuthor: TLabel;
    procedure btnSniffClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    WantToClose: boolean;
  public
    // public
  end;

var
  frmMain: TfrmMain;

const
  LOOP: array [0..1] of Byte = ($EB,$FE);

implementation

{$R *.dfm}

function SniffSerial(PI: PROCESS_INFORMATION; Ctx: _Context): string;
var
  X: Cardinal;
  Buff: PChar;
begin
  GetMem(Buff,50);

	SuspendThread(PI.hThread);
	GetThreadContext(PI.hThread,Ctx);
	ReadProcessMemory(PI.hProcess,Pointer(Ctx.Eax),Buff,50,X);

  Result:=Trim(Buff);
  FreeMem(Buff);
end;

procedure TfrmMain.btnSniffClick(Sender: TObject);
var
  PI: PROCESS_INFORMATION;
  SI: STARTUPINFO;
	Context: _CONTEXT;
  Buffer: PChar;
  ORIG: array [0..1] of Byte;
  S: string;
  W: DWORD;
begin
  // disable button (avoid starting target multiple times)
  btnSniff.Enabled:=False;

  GetMem(Buffer,255);
  FillChar(PI,SizeOf(TProcessInformation),#0);
  FillChar(SI,SizeOf(TStartupInfo),#0);
	SI.cb:=SizeOf(SI);

  if not CreateProcess('CrackMe.exe',nil,nil,nil,False,
                       CREATE_SUSPENDED,nil,nil,SI,PI) then
  begin
    // enable button
    btnSniff.Enabled:=True;

    // set log and exit
    lblLog.Caption:='Failed to load process!';
    Exit;
  end;

  // read original bytes
  ReadProcessMemory(PI.hProcess,Pointer($004503EF),@ORIG,2,W);

  // set inifnite loop
	WriteProcessMemory(PI.hProcess,Pointer($004503EF),@LOOP,2,W);

  // resume the program
	ResumeThread(PI.hThread);
	Context.ContextFlags:=$00010000+15+$10;

  // set new log
  lblLog.Caption:='Process patched!'+#13+
                  'Now enter a name and press the "Check" button...';

	while GetThreadContext(PI.hThread,Context) do
  begin
    // did we arrived at the infinite-loop?
		if Context.Eip=$004503EF then
    begin
      // sniff the serial and put it into "S"
      S:=SniffSerial(PI,Context);

      // restore original bytes and resume the target
    	WriteProcessMemory(PI.hProcess,Pointer($004503EF),@ORIG,2,W);
      ResumeThread(PI.hThread);

      // copy the serial into the clipboard
      Clipboard.AsText:=S;
      lblLog.Caption:='Your serial has been copied to clipboard!';
    end;

    // wait a little
		Sleep(10);
    Application.ProcessMessages;

    // close the CrackMe before closing the Snifer
    if WantToClose then
    begin
      TerminateThread(PI.hThread,0);
      Close;
    end;
	end;

  // free memory
  FreeMem(Buffer);

  // enable button
  btnSniff.Enabled:=True;
end;

procedure TfrmMain.btnCloseClick(Sender: TObject);
begin
  WantToClose:=true;
  Close;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  WantToClose:=false;
end;

end.
