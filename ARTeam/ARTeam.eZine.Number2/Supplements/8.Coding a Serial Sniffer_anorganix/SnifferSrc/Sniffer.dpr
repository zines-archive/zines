program Sniffer;

uses
  Forms,
  main in 'main.pas' {frmMain};

{$R *.res}

begin
  Application.Initialize;
  Application.Title := 'CrackMe Sniffer';
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
