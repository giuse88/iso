LATEX_BUILDER=pdflatex
BIB_BUILDER=bibtex

all : build_document

build_no_bliography: report.tex  
	$(LATEX_BUILDER) report.tex

bibliography : report.aux 
	$(BIB_BUILDER) report.aux

build_document: build_no_bliography  bibliography
	$(LATEX_BUILDER) report.tex

clean :
	rm -f *.out  *.brf *.blg *.lof *.log *.nlo *.aux *.toc *.pdf *.bbl
