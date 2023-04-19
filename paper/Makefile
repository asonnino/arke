.PHONY: FORCE lenny all clean distclean

FILE=main

all: $(FILE).pdf

%.pdf: %.tex FORCE
	latexmk -pdf $<

%.ps: %.tex FORCE
	latexmk -ps $<

fast:
	pdflatex $(FILE)

allx:
	pdflatex $(FILE)
	bibtex $(FILE)
	pdflatex $(FILE)
	pdflatex $(FILE)


clean:
	for ext in aux log toc lof lot lol dlog bbl \
		nav snm fls vrb blg out tpt fdb_latexmk; \
	do \
		$(RM) $(FILE).$$ext ; \
	done
	$(RM) *.aux *.bak *~

distclean: clean
	$(RM) $(FILE).pdf
	$(RM) $(FILE).ps
	$(RM) $(FILE).dvi
	$(RM) *.d
