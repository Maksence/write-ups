# Password-guesser
## Reverse challenge
> Description:
If you give me the password I'll give you the flag
> 
>Files: password-guesser.elf

You are given an elf-file. If you execute it, a window appears and prompts you to enter a password in exchange for the flag.

![Program](https://github.com/Maksence/write-ups/blob/main/THCon2024/images/Program.png)

The first question you should ask yourself is what was it compiled with/what langage was it written in.

Ghidra doesn't seem to recognize it, and its analysis just outputs some incomprehensible mess.

Let's take a look at the strings of the file:
```shell
strings password-guesser.elf
```
And in the output at the bottom we find something interesting...
```shell
4libpython3.8.so.1.0
```
Could it be a python program ? Let's confirm our thoughts by grepping for some more python references in the program. We can use the "-a" option to tell grep to treat the binary as a text.
```shell
$ grep -a "python" password-guesser.elf 
Failed to pre-initialize embedded python interpreter!
Failed to allocate PyConfig structure! Unsupported python version?
Failed to set python home path!
Failed to start embedded python interpreter!
[...]
```

Some logs of a python interpreter. So it definitely is python. But if we know anything about Python, it's that Python doesn't produce actual executable programs when ran but rather creates bytecode representations of the code which is then executed.

So this must mean that an intermediary must have been used to compile all the python bytecode and dependencies into a single file.

Now, we can either try to guess which tool was used and look for the most common ones, or we can dig a bit deeper.

Using [Binary Ninja](https://binary.ninja/), we can decompile our code and look for potential references to the tool used. Searching in the vicinity of "python" references, sure enough we find the following

![binary_ninja](https://github.com/Maksence/write-ups/blob/main/THCon2024/images/binary_ninja.png)

[PyInstaller](https://pyinstaller.org/en/stable/) is the tool that was used.

> PyInstaller bundles a Python application and all its dependencies into a single package. The user can run the packaged app without installing a Python interpreter or any modules. PyInstaller supports Python 3.8 and newer, and correctly bundles many major Python packages such as numpy, matplotlib, PyQt, wxPython, and others.

Now we just need to find a decompiler.
[pyinstallerextractor](https://github.com/extremecoders-re/pyinstxtractor) should do it.

Use it:
```shell
python pyinstxtractor.py password-guesser.elf
```

![pyinstallerextractor](https://github.com/Maksence/write-ups/blob/main/THCon2024/images/pyinstallerextractor.png)

And now we have the bytecode of our program.
There are a lot of files, but the only one that we're interested in is password-guesser.pyc, which is the bytecode of the actual original python program.

We need to turn this bytecode into readable code.

We're going to need another tool such as [uncompyle6](https://pypi.org/project/uncompyle6/)
>uncompyle6 translates Python bytecode back into equivalent Python source code.

```shell
$ uncompyle6 password-guesser.pyc
# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.0 (default, Feb 14 2024, 18:57:40) 
# [GCC 13.2.1 20231205 (Red Hat 13.2.1-6)]
# Embedded file name: password-guesser.py
[...]
```
And we get the program as an output!
```python
import tkinter as tk
from tkinter import messagebox
import base64

def reveal():
    f1 = 'Zm'
    f5 = 'PTntz'
    f6 = 'b01V'
    f7 = 'Q0h'
    f10 = 'RklM'
    f12 = 'aVozf'
    f13 = 'Q=='
    f11 = 'RV9z'
    f8 = 'fNF90a'
    f9 = 'DNf'
    f2 = 'xh'
    f3 = 'Zz1U'
    f4 = 'SEN'
    a = ''
    fragments = ['f{}'.format(i) for i in range(1, 14)]
    for i in range(0, 13):
        a += locals()[fragments[i]]
    else:
        b = base64.b64decode(a).decode('utf-8')
        return b


class App(tk.Frame):

    def __init__(self, master):
        self.master = master
        self.master.title('Password guesser')
        self.master.geometry('600x150')
        lbl1 = tk.Label((self.master), text="If you give me the password I'll give you the flag \n :)", font='Helvetica 11 bold')
        lbl1.grid(row=0, column=1, columnspan=5, ipadx=10, ipady=5)
        self.entry1 = tk.Entry((self.master), width=30, show='*')
        self.entry1.grid(row=1, column=1, padx=170)
        btn1 = tk.Button((self.master), text='Submit', command=(self.check_password))
        btn1.grid(row=2, column=1)
        self.lbl3 = tk.Label((self.master), text='Please type your password and click submit to continue.', font='Helvetica 11 italic')
        self.lbl3.grid(row=3, column=1)

    def check_password(self):
        password = self.entry1.get()
        success = 'Password correct, congrats!'
        facile = 'Easy enough, right?'
        bravo = 'congrats :)'
        if not password == 'password':
            if password == 'admin' or password == 'root':
                self.lbl3.config(text='Nice try, not the password though.')
        elif password == 'never gonna give you up' or password == 'nevergonnagiveyouup':
            self.lbl3.config(text='never gonna let you down, never gonna run around and desert you :)')
        else:
            rem = len(password) % 4
            if rem == 0:
                self.lbl3.config(text='Password incorrect, make sure you have entered your password correctly')
            if rem == 1:
                self.lbl3.config(text="That's not the password, try again!")
            if rem == 2:
                self.lbl3.config(text='This might take a while... not the password')
            if rem == 3:
                self.lbl3.config(text='Wrong password. Better luck next time')
        if password == "Don't actually try to bruteforce! It's not that hard.":
            self.lbl3.config(text=success)
            messagebox.showinfo(facile, bravo, detail=(reveal()))
            self.master.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    myapp = App(root)
    root.eval('tk::PlaceWindow . center')
    root.mainloop()
```

The "reveal" function quite obviously contains an obfuscated flag. We can run it locally, or just use the password *"Don't actually try to bruteforce! It's not that hard."* in the program, and get the flag.

![flag](https://github.com/Maksence/write-ups/blob/main/THCon2024/images/flag.png)
