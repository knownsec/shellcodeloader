@echo Off
del /s /a  *.db *.txt *.exe *.suo *.ncb *.user *.dll *.pdb *.netmodule *.aps *.ilk 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d/x64" 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d/Debug" 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d/Release" 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d/Bin" 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d/Obj" 2>nul

pause