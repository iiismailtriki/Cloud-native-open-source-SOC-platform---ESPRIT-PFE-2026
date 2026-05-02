REPORT = pfe-report
LATEX  = pdflatex
BIBTEX = bibtex

.PHONY: all clean distclean

all: $(REPORT).pdf

$(REPORT).pdf: $(REPORT).tex
	$(LATEX)  -interaction=nonstopmode $(REPORT).tex
	$(LATEX)  -interaction=nonstopmode $(REPORT).tex
	$(LATEX)  -interaction=nonstopmode $(REPORT).tex

clean:
	rm -f $(REPORT).aux $(REPORT).log $(REPORT).toc \
	       $(REPORT).lof $(REPORT).lot $(REPORT).out \
	       $(REPORT).bbl $(REPORT).blg $(REPORT).bak

distclean: clean
	rm -f $(REPORT).pdf
