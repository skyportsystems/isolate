DEBUILD = debuild -b -us -uc

deb:
	cd build; $(DEBUILD)

clean:
	cd build; $(DEBUILD) -Tclean
	rm -f *.deb *.changes *.build

dch:
	cd build; EMAIL="$(shell git config --get user.name) <$(shell git config --get user.email)>" dch -i

.PHONY: deb clean dch
