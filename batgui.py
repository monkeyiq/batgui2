#!/usr/bin/env python

# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details
##
## Updated to use PyQt and QWebView in 2015 by Ben Martin
##

'''
This is a program for viewing results of the Binary Analysis Tool.
'''


import sys, os, string, gzip, cPickle, bz2, tarfile, tempfile, copy
from   optparse import OptionParser
from enum       import Enum
from os.path    import isfile
import ConfigParser
from batpyqtgui             import Ui_batpyqtgui
from batpyqtguifilterdialog import Ui_FilterDialog
from PyQt5                  import QtCore, QtGui
from PyQt5.QtGui            import QStandardItemModel, QStandardItem
from PyQt5.QtCore           import QAbstractItemModel, QFile, QIODevice, QModelIndex, Qt
from PyQt5.QtCore           import QSortFilterProxyModel, QRegExp, QDateTime, QDate, QTime
from PyQt5.QtCore           import QItemSelectionModel, QVariant
from PyQt5.QtWidgets        import QApplication, QDialog, QMainWindow, QWidget, QFileDialog
from PyQt5.QtWidgets        import QHeaderView, QErrorMessage, QMessageBox
from PyQt5.QtWebKitWidgets  import QWebView
import sqlite3, cgi

'''
    Each column in the batgui.treeview is described here, some of the columns are
    not displayed and are for internal use only
'''
class MainTreeCol(Enum):
    Name  = 0    # Shown: decorated file name that is shown in the tree
    Mask  = 1    # Shown: mask describing object, like a circled D for directories
    Path  = 2    # full path of the file/dir
    HexdumpExtractFailed = 3 # have already tried to get hex dump report and failed for this entry
    Extra = 4    # mainly for testing
    _Max = Extra
    


def QMIToPath(proxyModel,qmi):
    """
    Given a QModelIndex and the model that it belongs too return the path
    associated with that model index
    """
    qmi = qmi.sibling(qmi.row(),MainTreeCol.Path.value);
    bb = proxyModel.data(qmi)
    return bb;

class treevisitor_PathToQMI_Data:
    def __init__(self, path):
        self.path = path
        self.qmi = None
        
def treevisitor_PathToQMI( model, node, arg ):
    """
    """
    j = QMIToPath(model,node)
    if arg.path == j:
        arg.qmi = node
        

def PathToQMI(proxyModel,path):
    """
    """
    arg = treevisitor_PathToQMI_Data( path  )
    treevisit( proxyModel, treevisitor_PathToQMI, arg )
    return arg.qmi

def QMIToValue(model,qmi,col):
    """
    Given a QModelIndex and the model that it belongs too return the Value
    associated with that model index
    """
    qmi = qmi.sibling(qmi.row(), col);
    bb = model.data(qmi)
    return bb;

def QMISetValue(model,qmi,col,v):
    """
    Given a QModelIndex and the model that it belongs too return the Value
    associated with that model index
    """
    qmi = qmi.sibling(qmi.row(),col);
    model.setData( qmi, v )

def treevisitCore( node, model, visitor, arg ):
    """
    Internal recursive function used by treevisit(). 
    """
    ch = node.child( 0,0 )
    while ch.isValid():
        j = QMIToPath(model,ch)
        visitor(model,ch,arg)
        treevisitCore( ch, model, visitor, arg )
        ch = ch.sibling(ch.row()+1,0)

def treevisitor_print( model, node, arg ):
    """
    Simple example visitor which prints the path of every item in the tree
    """
    j = QMIToPath(model,node)
    print "arg:", arg, " child: ", j


def treevisit( model, visitor = treevisitor_print, arg = 1 ):
    """
    Run the given 'visitor' function on every item in the Qt Tree Model. arg is passed 
    as the final argument to your visitor function to let you pass in extra data.
    """
    node = model.index( 0, 0 )
    ch = node
    while ch.isValid():
        j = QMIToPath(model,ch)
        visitor(model,ch,arg)
        treevisitCore( ch, model, visitor, arg )
        ch = ch.sibling(ch.row()+1,0)
    



class myTreeFilterProxyModel(QSortFilterProxyModel):
    """ Allow filtering the treeview without throwing away the entries.
    """
    def __init__(self, batgui, parent=None):
        super(myTreeFilterProxyModel, self).__init__(parent)
        self.batgui = batgui

    def filterChanged(self):
        self.invalidateFilter()
        
    def filterAcceptsRow(self, sourceRow, sourceParent):
    
        qmi = self.sourceModel().index(sourceRow, 0, sourceParent)
        if not qmi.isValid():
            return False
        filters = self.batgui.filters
        unpackreports = self.batgui.unpackreports
        path = QMIToPath(self.sourceModel(),qmi)
        # item = self.sourceModel().data(qmi)
#        print "filter() path:", path

        # if tags, symlink (which is a tag), or file size
        # mean we should ignore the entry then do so.
        if unpackreports.has_key(path):
            report = unpackreports[path]
	    if report.has_key('tags'):
                tags = report['tags']
                #print "has tags:", tags
		if list(set(tags).intersection(set(filters))) != []:
                    return False
	    if report.has_key('size'):
		if report['size'] == 0:
		    if "empty" in filters:
                        return False
                
        ## Remove empty, or seemingly empty, directories from the
	## view to declutter the interface.
	## We keep traversing the tree until we know for sure that
	## there are only directories with visible items left. There
	## is probably a more efficient way, but this is still fast.
	if self.batgui.filterForceRemoveEmptyDirectories or "emptydir" in filters:
            ch = qmi.child( 0,0 )
            removeDirectory = ch.isValid()
            while ch.isValid():
                # item = self.sourceModel().data(ch)
                # path = QMIToPath(self.sourceModel(),ch)
                
                if self.filterAcceptsRow( ch.row(), qmi ):
                    return True
                ch = ch.sibling(ch.row()+1,0)
            if removeDirectory:
                return False

        # do the default thing.
        return super(myTreeFilterProxyModel, self).filterAcceptsRow(sourceRow, sourceParent)

    def filterAcceptsColumn( self, sourceRow, sourceParent):
        return True
        

            
""" This is the main object of the application.
"""
class StartBATGUI(QMainWindow):

        def getSHADigestFromPath(self,path):
            sha256sum = ''
            if self.unpackreports.has_key(path):
	      tag = ''
	      if self.unpackreports[path].has_key('checksum'):
	        sha256sum = self.unpackreports[path]['checksum']
            return sha256sum

        @QtCore.pyqtSlot(result=str)
        def getActivePath( self ):
            return self.selectedfile
        
        @QtCore.pyqtSlot(str,str,result=str)
        def getHexdump(self,key,page):
            """
            Find the report for the entry from the main qtreeview with the path 'key'
            then read and return the selected 'page' from the archive.
            """
            print "getHexdump() key:", key, " sel:", self.selectedfile
            qmi = PathToQMI(self.proxyModel,key)
    	    sha256sum = self.getSHADigestFromPath(key)
            if sha256sum == '':
                return "<p>No report for path:%s </p>" % key

            qmi = PathToQMI(self.proxyModel,key)
            print "AAA qmi: ", qmi
            print "AAA qmi.v: ", QMIToValue( self.proxyModel, qmi, MainTreeCol.HexdumpExtractFailed.value )
            if QMIToValue( self.proxyModel, qmi, MainTreeCol.HexdumpExtractFailed.value ) != 1:
                QMISetValue( self.proxyModel, qmi, MainTreeCol.HexdumpExtractFailed.value, 1 )

                reportpath = "reports/%s-%s.gz" % (sha256sum,page)
                print "reportpath:", reportpath
                print "self.tarfile:", self.tarfile
                print "self.tmpdir:", self.tmpdir

		tar = self.openTar( self.tarfile )
		self.tarmembers = tar.getmembers()
		members = []
		members = members + filter(lambda x: x.name == reportpath, self.tarmembers)
		tar.extractall(self.tmpdir, members)
		tar.close()
                
            reportpath = os.path.join(self.reportsdir, "%s-%s.gz" % (sha256sum,page))
            print "Trying to extract hexdump report:", page
            print "__________looking for:", reportpath
	    if os.path.exists(reportpath):
                lineLimit = 1000
	        # data = self.readFile(reportpath)
                # Dont use readFile() for this, because we want to decorate each
                # line with some HTML
                data = ""
                i = 1
                lines = [];
                theFile = gzip.open(reportpath, 'r')
	        for line in theFile:
		    l = '<tr><td class="codeline">' + line + '</td>'
		    l = l + ' <td class="codemeta" id="hexline%d"></td></tr>' % i
                    i = i + 1
                    lines.append(l)
                    if i >= lineLimit:
                        break
                    
                theFile.close()
                data = '<table class="table">\n' + ''.join(lines) + '</table>'
	        data = data.replace('REPLACEME', self.imagesdir)
                return data
            else:
                return "<p>No report for path:%s </p>" % key
            return "<p>failed to find report for page: %s</p>" % (key)
        
    
        @QtCore.pyqtSlot(str,str,result=str)
        def getPage(self,key,page):
            """
            Find the report for the entry from the main qtreeview with the path 'key'
            then read and return the selected 'page' from the archive.
            """
            print "getPage() key:", key, " sel:", self.selectedfile
            if page == "hexdump":
                return self.getHexdump( key, page )

    	    sha256sum = self.getSHADigestFromPath(key)
            if sha256sum == '':
                return "<p>No report for path:%s </p>" % key

            reportpath = os.path.join(self.reportsdir, "%s-%s.html.gz" % (sha256sum,page))
	    if os.path.exists(reportpath):
	       elfhtml = self.readFile(reportpath)
	       elfhtml = elfhtml.replace('REPLACEME', self.imagesdir)
               return elfhtml
            else:
                reportpath = os.path.join(self.reportsdir, "%s-%s.gz" % (sha256sum,page))
                print "__________looking for:", reportpath
	        if os.path.exists(reportpath):
	            elfhtml = self.readFile(reportpath)
	            elfhtml = elfhtml.replace('REPLACEME', self.imagesdir)
                    return elfhtml
                else:
                    return "<p>No report for path:%s </p>" % key
            return "<p>failed to find report for page: %s</p>" % (key)

        @QtCore.pyqtSlot(result=str)
        def getScriptDir(self):
                return self.scriptDir

        @QtCore.pyqtSlot(result=str)
        def getHTMLDir(self):
            print "getHTMLDir() ret:", self.htmldir
            return self.htmldir

        """Read a file, either from local storage or from inside a tar
        archive. Data read from files which are bz2 encoded is
        uncompressed before being returned.

        Limitations: at the moment only local gz and bz2 files are supported.
        """
        @QtCore.pyqtSlot(str,result=str)
        def readFile(self,p):
            print "readFile() p-->:%s:<--" % p
            if p.endswith(".gz"):
                theFile = gzip.open(p, 'r')
	        data = theFile.read()
	        theFile.close()
                return data

	    theFile = bz2.BZ2File(p, 'r')
	    data = theFile.read()
            theFile.close()
            print "readFile() data:", data
            return data
            
        """ Basedir where the css, js, and other web assets can be loaded from
        """
        @QtCore.pyqtSlot(str,result=str)
        def getWebResourceDir(self,p):
                return self.scriptDir + '/batguiresources/' + p

        @QtCore.pyqtSlot(str,result=str)
        def getWebResourceUrl(self,p):
                return 'file://' + self.getWebResourceDir(p)

        @QtCore.pyqtSlot("int",result=str)
	def getFromInt(self,intv):
            return "nothing"
            
        @QtCore.pyqtSlot(str,result=QVariant)
	def test2(self,path):
            ret = ['a','b','c']
            #return QVariant(ret)
            unpackedfiles = []
	    unpackedfiles.append([101, 'barry1', 204])
	    unpackedfiles.append([201, 'barry2', 204])
	    unpackedfiles.append([301, 'barry3', 204])
            print "test2:", unpackedfiles
            return unpackedfiles;

        
        @QtCore.pyqtSlot(str,result=QVariant)
	def getScanHighlights(self,path):
		unpackedfiles = []
                if not self.unpackreports.has_key(path) or not self.unpackreports[path].has_key('scans'):
                    return []

		for i in self.unpackreports[path]['scans']:
			unpackedfiles.append(( i['offset'], i['scanname'], i['size'] ))

		## work our way backwards, so we don't have to remember to do funky math with offsets
		unpackedfiles = sorted(unpackedfiles, reverse=True)
                print "unpackedfiles.len:", len( unpackedfiles )

                ## remove the use of tuple so we can pass it back to javascript.
                ret = []
                for i in unpackedfiles:
                    ret.append([ i[0], i[1], i[2] ])
                    
                print "ret:", ret
                return ret
                
        def setupFromBAT(self):
            self.treemodel.removeRows(0,self.treemodel.rowCount())
            
            parent   = self.treemodel.invisibleRootItem()
            rootnode = parent
            parents  = [parent]
            columnData = ['hi','there']
    	    nodes = {}


 	    dirlist = list(set(map(lambda x: os.path.dirname(x), self.unpackreports.keys())))

	    ## make sure that we have all directories
	    for d in dirlist:
	        if os.path.dirname(d) in dirlist:
	            continue
	        else:
	            dirlist.append(os.path.dirname(d))
	    dirlist.sort()


	    for d in dirlist:
	      if d == "":
	        continue
	      else:
	        if d.startswith('/'):
	          d = d[1:]
	        parent = os.path.dirname(d)
	        if parent == "":
	          linktext = u"%s" % d
                  masktext = u"\u24b9"
                  dirnode = self.appendChild(self.treemodel, rootnode, linktext, masktext, d )
	          nodes[d] = dirnode
	        else:
	          ## length of parent, plus 1 for trailing slash
	          parentlen = len(parent) + 1
              
	          ## check if the parent directory is actually there. If not, we have
	          ## a problem. Should not occur.
	          if not nodes.has_key(parent):
		    continue
                  linktext = u"%s" % d[parentlen:]
                  masktext = u"\u24b9"
                  dirnode = self.appendChild( self.treemodel, nodes[parent], linktext,masktext,os.path.normpath(d))
	          nodes[d] = dirnode

	    filelist = self.unpackreports.keys()
	    filelist.sort()
        

	    for j in filelist:
		    if j.startswith('/'):
			    j = j[1:]
		    parent = os.path.dirname(j)
		    ## length of parent, plus 1 for trailing slash
		    parentlen = len(parent) + 1
		    ignore = False
		    if parent == "":
			    linktext = j
		    else:
			    linktext = j[parentlen:]
		    tagsentities = {'text': u'\u24c9', 'graphics': u'\u24bc', 'compressed': u'\u24b8', 'resource': u'\u24c7', 'static': u'\u24c8', 'dalvik': u'\u24b6', 'ranking': u'\u272a', 'linuxkernel': u'\u24c1', 'duplicate': u'\u229c'}
                    masktext = ''
                
		    if self.unpackreports[j].has_key('tags'):
			    for t in self.unpackreports[j]['tags']:
				    if list(set(self.unpackreports[j]['tags']).intersection(set(self.filters))) != []:
					    ignore = True
					    continue
				    tagappend = u""
				    if tagsentities.has_key(t):
					    tagappend = tagsentities[t]
				    if tagappend != u"":
                                            masktext = masktext + u"  %s" % tagappend
			    if "symlink" in self.unpackreports[j]['tags']:
				    if "symlink" in self.filters:
					    ignore = True
					    continue
				    ## if it is a link, then add the value of where the link points to
				    ## to give a visual clue to people
				    ## example: "symbolic link to `../../bin/busybox'"
				    linkname = self.unpackreports[j]['magic'][:-1].rsplit("symbolic link to `", 1)[-1]
				    linktext = u"%s \u2192 %s" % (linktext, linkname)
		    if self.unpackreports[j].has_key('size'):
			    if self.unpackreports[j]['size'] == 0:
				    ## if files are empty mark them as empty
				    if "empty" in self.filters:
					    ignore = True
				    else:
					    masktext = u"\u2205"
		    if ignore:
			    continue
		    if parent == "":
                            leafnode = self.appendChild( self.treemodel, rootnode, linktext,masktext,j)
			    nodes[j] = leafnode
		    else:
			    if not nodes.has_key(parent):
				    continue
			    else:
                                    leafnode = self.appendChild(self.treemodel, nodes[parent],linktext,masktext,os.path.normpath(j))
				    nodes[j] = leafnode

        
	    ## Remove empty, or seemingly empty, directories from the
	    ## view to declutter the interface.
	    ## We keep traversing the tree until we know for sure that
	    ## there are only directories with visible items left. There
	    ## is probably a more efficient way, but this is still fast.
	    if "emptydir" in self.filters:
		    stillempty = True
		    while stillempty:
			    stillempty = False
			    for i in dirlist:
				    if nodes.has_key(i):
					    if not nodes[i].ItemHasChildren():
						    nodes[i].remove()
						    del nodes[i]
						    stillempty = True
                                          
            self.treeview.expandAll()

        """ Main GTreeModel: Add a new child node to the given parentNode with the associated
            data linktext, masks, path, (and possibly future subsequent args)
        """
        def appendChild(self, model, parentNode, linktext, masks, path, HexdumpExtractFailed = False ):
            item = QStandardItem( linktext )
            parentNode.appendRow([ item,
                                   QStandardItem( masks ),
                                   QStandardItem( path ),
                                   QStandardItem( HexdumpExtractFailed )
                                   ])
            return item
        
        """ Use with self.filterdialog.Model: add a new entry to the list at the top level
            with the given text
        """
        def addFilterDialogItem(self, model, txt ):
                tfitem = QStandardItem( txt )
                tfitem.setCheckable( True )
                tfitem.setFlags( Qt.ItemIsUserCheckable
                                 | Qt.ItemIsEnabled
                                 | Qt.ItemNeverHasChildren )
                model.appendRow([ tfitem ])
            
            
	def __init__(self, scriptDir, parent=None):
		QMainWindow.__init__(self, parent)

                self.scriptDir = scriptDir;
		self.ui = Ui_batpyqtgui()
		self.ui.setupUi(self)
                self.ui.splits.setStretchFactor( 0, 4 )
                self.ui.splits.setStretchFactor( 1, 2 )

		## initial values of filters
                self.filterForceRemoveEmptyDirectories = False
		self.filterconfigstate = []
		self.filters = []
		self.filterconfig = [(["audio", "mp3", "ogg"], "Audio files"),
                                     (["duplicate"], "Duplicate files"),
                                     (["emptydir"], "Empty directories (after filters have been applied)"),
                                     (["empty"], "Empty files"),
                                     (["png", "bmp", "jpg", "gif", "graphics"], "Graphics files"),
                                     (["pdf"], "PDF files"),
                                     (["resource"], "Resource files"),
                                     (["symlink"], "Symbolic links"),
                                     (["text", "xml"], "Text files"),
                                     (["video", "mp4"], "Video files"),]
#                self.tree = 'fixme'

                self.unpackreports = {}
                
		self.filterdialog = Ui_FilterDialog()
                self.filterdialogwindow = QDialog()
                self.filterdialogwindow.batpyqtgui = self
		self.filterdialog.setupUi(self.filterdialogwindow)
                self.filterdialog.Model = QStandardItemModel(0,1,parent)
                model = self.filterdialog.Model;
                model.setHeaderData(0, Qt.Horizontal, "Filter")
                self.addFilterDialogItem( model, "Audio files" )
                self.addFilterDialogItem( model, "Duplicate files" )
                self.addFilterDialogItem( model, "Empty directories (after filters have been applied)" )
                self.addFilterDialogItem( model, "Empty files" )
                self.addFilterDialogItem( model, "Graphics files" )
                self.addFilterDialogItem( model, "PDF files" )
                self.addFilterDialogItem( model, "Resource files" )
                self.addFilterDialogItem( model, "Symlink files" )
                self.addFilterDialogItem( model, "Text files" )
                self.addFilterDialogItem( model, "Video files" )
                h = self.filterdialog.listView.horizontalHeader()
                h.setStretchLastSection( True )
                self.filterdialog.listView.setModel(model)
                self.filterdialog.listView.verticalHeader().hide();
                self.filterdialog.listView.horizontalHeader().hide();

                # setup webview widget
                webview = self.ui.web;
                self.webview = self.ui.web
                webview.page().mainFrame().javaScriptWindowObjectCleared.connect(
                        self.populateJavaScriptWindowObject )
                webview.setUrl(QtCore.QUrl(self.getWebResourceUrl('/index.html')))

               
                #self.ui.button_open.clicked.connect(self.file_open_test)
                self.ui.action_test.triggered.connect(self.onTest)
                self.ui.find.returnPressed.connect(self.onFind)


                    
                self.treeview  = self.ui.tree
                self.treemodel = QStandardItemModel(0,MainTreeCol._Max.value,parent)
                self.proxyModel = myTreeFilterProxyModel(self)
                self.proxyModel.setSourceModel( self.treemodel )
                self.treeview.setModel( self.proxyModel )
                regExp = QRegExp(".*", Qt.CaseSensitive, QRegExp.PatternSyntax(QRegExp.RegExp))
                self.proxyModel.setFilterRegExp(regExp)
                self.proxyModel.setFilterKeyColumn( 0 )
                self.treemodel.setHeaderData( MainTreeCol.Name.value,  Qt.Horizontal, "Name")
                self.treemodel.setHeaderData( MainTreeCol.Mask.value,  Qt.Horizontal, "Masks")
                self.treemodel.setHeaderData( MainTreeCol.Extra.value, Qt.Horizontal, "Extra")
                self.treemodel.setHeaderData( MainTreeCol.Path.value,  Qt.Horizontal, "FullPath")
                self.treemodel.setHeaderData( MainTreeCol.HexdumpExtractFailed.value,  Qt.Horizontal, "HexdumpExtractFailed")
                self.treeview.setColumnHidden( MainTreeCol.Extra.value, True )
                self.treeview.setColumnHidden( MainTreeCol.Path.value,  True )
                self.treeview.setColumnHidden( MainTreeCol.HexdumpExtractFailed.value,  True )
#                self.treeview.clicked.connect(self.onTreeClicked);
                self.treeview.selectionModel().currentChanged.connect(self.onTreeClicked);
                #self.treeview.header.resizeColumnToContents(1)
                self.treeview.header().setStretchLastSection( False )
                self.treeview.header().setSectionResizeMode( 0, QHeaderView.Stretch )

                
		## some defaults
		self.datadir = ""
		self.tarfile = None
		self.timer = None
		self.selectedfile = None
		self.htmldir = None
                self.htmldir = "/tmp/htmldir" # FIXME

		## we start in "simple" mode
		self.advanced = True
		self.advancedunpacked = False
		self.batconfig = ["Advanced mode"]
		self.batconfigstate = []

                self.ui.FindArea.hide()

        def onTreeClicked(self,qmi,oldqmi):
            self.onTreeClicked(qmi)
                
        def onTreeClicked(self,qmi):
                print "onTreeClicked.............."
                print "qmi:", qmi
                frame = self.ui.web.page().mainFrame()
                path = QMIToPath(self.proxyModel,qmi)
                self.selectedfile = path
                print "onTreeClicked! path:", path

    	        sha256sum = self.getSHADigestFromPath( path )
                if sha256sum == '':
                    name = "";
                    realpath =""
                    magic = ""
		    size = "0"
                    if self.unpackreports.has_key(path):
                        name = self.unpackreports[path]['name']
		        realpath = self.unpackreports[path]['realpath']
		        magic = self.unpackreports[path]['magic']
                        
                    frame.evaluateJavaScript('OnFileWithoutReportsSelected("' + path
                                             + '", "' + name
                                             + '", "' + realpath
                                             + '", "' + size
                                             + '", "' + magic
                                             + '");' )
                    return
                
                res = frame.evaluateJavaScript('OnFileSelected("' + path + '");')
                print "OnFileSelected():", res
                
                    
        def populateJavaScriptWindowObject(self):
                self.ui.web.page().mainFrame().addToJavaScriptWindowObject('batgui', self)
      


        """ 
        Get a file path from the user. Returns a file path. 
        Hides the QFileDialog return type marshaling
        """
        def runDialogToGetFilePath(self):
		fd = QFileDialog(self)
		filename = fd.getOpenFileName()
                filename = filename[0]
                return filename
            
	def onOpenFile(self):
                filename = self.runDialogToGetFilePath()
                self.openFile( filename )

	def openFile(self, filepath ):
            print "showing file: ", filepath
	    if isfile(filepath):
                self.openBATFile( filepath )
            else:
                self.showError('You did not select a valid file')
                
            
                    

	def onConfigurationOpen(self):
            try:
                filename = self.runDialogToGetFilePath()
                print "opening config file... :", filename
  	        config = ConfigParser.ConfigParser()
		configfile = open( filename, 'r' )
		config.readfp(configfile)
                self.setConfig(config)
	    except Exception, e:
                self.showError('Not a valid configuration file')

        def showError(self,msg):
            m = QErrorMessage()
            m.showMessage( msg )
            
                
	def onOpenFilterDialog(self):
                print "onOpenFilterDialog()..."
                model = self.filterdialog.Model;

                for row in range( model.rowCount() ):
                    model.setData( model.index(row,0), Qt.Unchecked, Qt.CheckStateRole )
                
                for f in self.filters:
                    #print "filter:", f
                    for row in range(len(self.filterconfig)):
                        if f in self.filterconfig[row][0]:
                            #print "checking for:", self.filterconfig[row][1]
                            model.setData( model.index(row,0), Qt.Checked, Qt.CheckStateRole )
                            
	        self.filterdialogwindow.show()

        def onFilterDialogAccepted(self):
                print "onFilterDialogAccepted()..."
                model = self.filterdialog.Model;
                self.filters = []
                for row in range( model.rowCount() ):
                    d = model.data( model.index(row,0), Qt.CheckStateRole )
                    if d > 0:
                        self.filters += self.filterconfig[row][0]
                    #print "d:", d
                #print "filters:", self.filters
                self.proxyModel.filterChanged()
                self.treeview.expandAll()
                
	def onTest(self):
                print "test..."
                print "  main:", self.ui.web.page().mainFrame()
                print "  main.p:", self.ui.web.page().mainFrame().parentFrame()
                print "  curr:", self.ui.web.page().currentFrame()
                print "  curr.p:", self.ui.web.page().currentFrame().parentFrame()
                frame = self.ui.web.page().mainFrame()
#                frame = self.ui.web.page().currentFrame()
                print frame.evaluateJavaScript('completeAndReturnName();')
                print frame.evaluateJavaScript('document.completeAndReturnName();')
#                print frame.evaluateJavaScript('completeAndReturnName();')
#                print frame.evaluateJavaScript('some_js_function(' + path + ')')
                
	def onFind(self):
            t = self.ui.find.text()
            self.setFind(t)
            
        def onFindClosed(self):
            self.setFind("")

        def setFind(self,t):
            print "find... text:", t
            self.filterForceRemoveEmptyDirectories = len(t) > 0
            regExp = QRegExp( t, Qt.CaseSensitive, QRegExp.PatternSyntax(QRegExp.RegExp))
            self.proxyModel.setFilterKeyColumn( 0 )
            self.proxyModel.setFilterRegExp(regExp)
            self.treeview.expandAll()
                

        def setConfig(self,config):
		self.origconfig = copy.copy(config)
		self.scanconfig = []
		for s in config.sections():
			if s == 'batconfig':
				continue
			elif s == 'viewer':
				if config.has_option(s, 'htmldir'):
					self.htmldir = config.get(s, 'htmldir')
			else:
				try:
					## process each section. We need: section name, description, enabled
					description = config.get(s, 'description')
					enabled = config.get(s, 'enabled')
					self.scanconfig.append((s, description, enabled))
				except:
					pass
		self.scanconfigstate = []
		for s in self.scanconfig:
			if s[2] == 'yes':
				self.scanconfigstate.append(self.scanconfig.index(s))
                
        def setup(self):
                print "setup..."

        def openTar( self, filepath, flags = 'r' ):
                print "openTar(1)"
		try:
                    tar = tarfile.open( filepath, "%s%s" % (flags,':gz'))
                    return tar
		except Exception, e:
                    tar = tarfile.open( filepath, flags)
                    return tar

	def openBATFile(self,filepath):
	        ## should be an archive with inside:
	        ## * scandata.pickle
	        ## * data directory
	        ## * images directory (optional)
	        self.tmpdir = tempfile.mkdtemp()
		try:
		  self.tarfile = filepath
#		  tar = tarfile.open(self.tarfile, 'r:gz')
                  tar = self.openTar( self.tarfile )
                  
		  self.tarmembers = tar.getmembers()
		  members = []
		  for i in ['scandata.pickle']:
		    members = members + filter(lambda x: x.name.startswith(i), self.tarmembers)

		  ## If we are not in advanced mode, there is no need to unpack everything. The hexdump
		  ## files and "TV static" pictures can be quite big, so don't unpack them when not needed.
		  if not self.advanced:
		    members = members + filter(lambda x: x.name.startswith('reports') and x.name.endswith('unique.html.gz'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('reports') and x.name.endswith('unmatched.html.gz'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('reports') and x.name.endswith('assigned.html.gz'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('reports') and x.name.endswith('guireport.html.gz'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('reports') and x.name.endswith('elfreport.html.gz'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('reports') and x.name.endswith('names.html.gz'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('images') and len(os.path.basename(x.name)) != 68, self.tarmembers)
		  else:
		    members = members + filter(lambda x: x.name.startswith('reports'), self.tarmembers)
		    members = members + filter(lambda x: x.name.startswith('images'), self.tarmembers)
                    
	          self.advancedunpacked = True
		  tar.extractall(self.tmpdir, members)
		  tar.close()
		except Exception, e:
		  os.rmdir(self.tmpdir)
		  return
		self.datadir = os.path.join(self.tmpdir, "data")
		self.imagesdir = os.path.join(self.tmpdir, "images")
		self.reportsdir = os.path.join(self.tmpdir, "reports")
		picklefile = open(os.path.join(self.tmpdir, "scandata.pickle") , 'rb')
		self.unpackreports = cPickle.load(picklefile)
		picklefile.close()
#		self.selectedfile = None
		self.initTree(self.datadir)
                

	def cleanWindows(self):
                print "cleanwindows..."
                frame = self.ui.web.page().mainFrame()
                frame.evaluateJavaScript('OnSelectionCleared();')
		# self.overviewwindow.SetPage(helphtml)
		# self.matcheswindow.SetPage('<html></html>')
		# self.matchesbrowser.SetPage("<html></html>")
		# self.unmatchedwindow.SetPage("<html></html>")
		# self.assignedwindow.SetPage("<html></html>")
		# self.nameswindow.SetPage("<html></html>")
		# self.functionmatcheswindow.SetPage('<html></html>')
		# self.elfwindow.SetPage("<html></html>")

                
	def initTree(self, tmpdir):
		if tmpdir == None:
			return
		self.cleanWindows()

                print "initTree() self.selectedfile:", self.selectedfile
                    
		## construct a tree from a pickle
		if tmpdir.endswith('/'):
			tmpdir = tmpdir[:-1]

                self.setupFromBAT()

                hadSelectedAnything = False
		if self.selectedfile != None:
                    print "reslectring self.selectedfile:", self.selectedfile
                    hadSelectedAnything = self.selectAndDisplay( self.selectedfile )

                #if not hadSelectedAnything:
		#    self.cleanWindows()
                    

        def treevisitor_selectFile( self, model, node, arg ):
            j = QMIToPath(model,node)
            #print "xx arg:", arg, " child: ", j
            if j == arg:
                self.hadSelectedAnything = True
                self.treeview.selectionModel().setCurrentIndex(
                    node,
                    QItemSelectionModel.Select | QItemSelectionModel.Rows  )
                self.onTreeClicked(node)

                
        """ Select the file in the main treeview with the given path and Scroll to show 
            it in the main UI
        """
        def selectAndDisplay( self, path ):
                print "selecting:", path
                self.treeview.clearSelection()
                self.hadSelectedAnything = False
                treevisit( self.proxyModel, self.treevisitor_selectFile, path )
                return self.hadSelectedAnything
                

                
if __name__ == "__main__":
        scriptDir = os.path.dirname(os.path.realpath(__file__))
  	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg",
                          help="path to configuration file", metavar="FILE")
	parser.add_option("-f", "--file",   action="store", dest="inputfilename",
                          help="path to bat-scan output file to open", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.cfg != None:
		try:
			configfile = open(options.cfg, 'r')
			config.readfp(configfile)
		except Exception, e:
			print >>sys.stderr, "Can not load your specified configuration file from:", options.cfg
                        print >>sys.stderr, "Reason:", e
			sys.exit(1)

	app = QApplication(sys.argv)
	myapp = StartBATGUI(scriptDir)
        myapp.setConfig(config)
        myapp.setup()
	myapp.show()

	if options.inputfilename != None:
	    myapp.openFile( options.inputfilename )
            
	sys.exit(app.exec_())
