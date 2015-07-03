all: Makefile batpyqtgui.py batpyqtguifilterdialog.py

batpyqtgui.py: batpyqtgui.ui Makefile
	pyuic5 batpyqtgui.ui >| batpyqtgui.py

batpyqtguifilterdialog.py: batpyqtguifilterdialog.ui Makefile
	pyuic5 batpyqtguifilterdialog.ui >| batpyqtguifilterdialog.py
