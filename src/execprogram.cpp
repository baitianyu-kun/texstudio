#include "execprogram.h"
#include "utilsSystem.h"
#include <QStandardPaths>

ExecProgram::ExecProgram(void) :
#ifdef Q_OS_WIN
	m_winProcModifier(nullptr),
#endif
	m_normalRun(false),
	m_exitCode(-1)
{
}

ExecProgram::ExecProgram(const QString &shellCommandLine, const QString &additionalSearchPaths, const QString &workingDirectory) :
	m_additionalSearchPaths(additionalSearchPaths),
	m_workingDirectory(workingDirectory),
#ifdef Q_OS_WIN
	m_winProcModifier(nullptr),
#endif
	m_normalRun(false),
	m_exitCode(-1)
{
	setProgramAndArguments(shellCommandLine);
}

ExecProgram::ExecProgram(const QString &progName, const QStringList &arguments, const QString &additionalSearchPaths, const QString &workingDirectory) :
	m_program(progName),
	m_arguments(arguments),
	m_additionalSearchPaths(additionalSearchPaths),
	m_workingDirectory(workingDirectory),
#ifdef Q_OS_WIN
	m_winProcModifier(nullptr),
#endif
	m_normalRun(false),
	m_exitCode(-1)
{
}

/*!
 * \brief Basic command-line parser
 * \details Basic command-line parser that splits a command-line into program name and arguments list.
 * The parsed program name and arguments are stored in class member variables.
 * The program name and each argument can be in one of the folloowing forms:
 *   A string without any whitespace, single quotes or double quotes, e.g. C:\Users\Steven\MyProgram.exe
 *   A double-quoted string. May contain whitespace, single quotes or backslash-escaped double quotes. For example "arg1='value1'"
 *   A single-quoted string. May contain whitespace, double quotes, backslash-escaped single quotes or. For example 'arg1="value1"' or 'arg1=\'value\''
 * As of now backslash escaped double-quotes are unusable because the option Tools/SupportShellStyleLiteralQuotes causes BuildManager::parseExtendedCommandLine() to
 * replace \" (backslash-escaped double-quotes) with """ (triple double-quotes)
 * TODO: Maybe improve the parser. We need to add proper quotes processing based on the OS type (UNIX/Win).
 * \param[in] shellCommandLine Shell command line that should be parsed.
 */
void ExecProgram::setProgramAndArguments(const QString &shellCommandLine)
{
	static const QRegularExpression rxSpaceSep("\\s+");
	Q_ASSERT(rxSpaceSep.isValid());
	static const QRegularExpression rxArgPiece(
		"("
			"[^[:space:]\"']+|"	// Non-whitespace string without any quotes
			"\"(\\\\\"|[^\"])*\"|"	// Double-quoted string. Any internal double-quotes are escaped as \"
			"'(\\\\'|[^'])*'"	// Single-quoted string. Any internal single-quotes are escaped as \'
		")",
		QRegularExpression::DontCaptureOption
	);
	Q_ASSERT(rxArgPiece.isValid());

	int shellLineLen = shellCommandLine.length();
	int shellLineOffset = 0;
	QStringList arguments;
	QString argText;
	bool argValid = false;
	for (;;) {
		if (shellLineOffset >= shellLineLen) {
			break;
		}
		QRegularExpressionMatch matchSpaceSep = rxSpaceSep.match(
			shellCommandLine,
			shellLineOffset,
			QRegularExpression::NormalMatch,
			QRegularExpression::AnchoredMatchOption
		);
		if (matchSpaceSep.hasMatch()) {
			if (argValid) {
				arguments.push_back(argText);
				argValid = false;
			}
			shellLineOffset += matchSpaceSep.capturedLength(0);
			if (shellLineOffset >= shellLineLen) {
				break;
			}
		}
		QRegularExpressionMatch matchArgPiece = rxArgPiece.match(
			shellCommandLine,
			shellLineOffset,
			QRegularExpression::NormalMatch,
			QRegularExpression::AnchoredMatchOption
		);
		if (matchArgPiece.hasMatch()) {
			int pieceLength = matchArgPiece.capturedLength(0);
			QString pieceText = matchArgPiece.captured(0);
			QChar firstChar = pieceText[0];
			if ((firstChar == '\'') || (firstChar == '"')) {
				pieceText = pieceText.mid(1, pieceLength - 2);
				pieceText.replace(QString("\\") + firstChar, firstChar);
			}
			if (argValid) {
				argText += pieceText;
			} else {
				argText = pieceText;
				argValid = true;
			}
			shellLineOffset += pieceLength;
		} else {
			// Malformed command-line remainder that starts with a dangling single or
			// double quote without a matching ending quote
			// Just skip the offending quote
			++shellLineOffset;
		}
	}
	if (argValid) {
		arguments.push_back(argText);
	}
	if (arguments.isEmpty()) {
		m_program = "";
		m_arguments.clear();
	} else {
		m_program = arguments.front();
		arguments.pop_front();
		m_arguments = arguments;
	}
}

bool ExecProgram::execAndWait(void)
{
	QProcess proc;

	execAndNoWait(proc);
	proc.waitForFinished();
	m_normalRun =
		(proc.error() == QProcess::UnknownError) &&
		(proc.exitStatus() == QProcess::NormalExit);
	m_exitCode = proc.exitCode();
	m_standardOutput = proc.readAllStandardOutput();
	m_standardError = proc.readAllStandardError();
	return m_normalRun && (m_exitCode == 0);
}

void ExecProgram::execAndNoWait(QProcess &proc) const
{
	if (!m_workingDirectory.isEmpty()) {
		proc.setWorkingDirectory(m_workingDirectory);
	}
	setWinProcModifier(proc);
	QString pathOrig = pathExtend();

#if defined(Q_OS_OHOS)
    QProcessEnvironment env = proc.processEnvironment();
    QString execPath = m_program;
    if (QFileInfo(execPath).isRelative()) {
        execPath = QStandardPaths::findExecutable(m_program, getEnvironmentPathList());
    }
    if (!execPath.isEmpty()) {
        QFileInfo fi(execPath);
        QString realPath = fi.canonicalFilePath();
        if (realPath.isEmpty()) realPath = fi.symLinkTarget();

        // OHOS HNP Symlink bypass: if sandbox blocks lstat, canonicalFilePath fails.
        // HNP installs binaries to /data/service/hnp/<vendor>/<name>_<version>/bin/
        // and symlinks them to /data/service/hnp/bin/
        if (realPath.isEmpty() && execPath.startsWith("/data/service/hnp/bin/")) {
            QDir baseDir("/data/service/hnp");
            QStringList vendors = baseDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QString& vendor : vendors) {
                if (vendor == "bin" || vendor == "lib") continue;
                QDir vendorDir(baseDir.absoluteFilePath(vendor));
                QStringList pkgs = vendorDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
                for (const QString& pkg : pkgs) {
                    QString possibleBin = vendorDir.absoluteFilePath(pkg) + "/bin/" + fi.fileName();
                    if (QFileInfo::exists(possibleBin)) {
                        realPath = possibleBin;
                        break;
                    }
                }
                if (!realPath.isEmpty()) break;
            }
            if (realPath.isEmpty()) { // ultimate fallback
                realPath = "/data/service/hnp/texlive.org/texlive_1.0.0/bin/" + fi.fileName();
            }
        } else if (realPath.isEmpty()) {
            realPath = execPath;
        }

        fi = QFileInfo(realPath);
        if (fi.isAbsolute()) {
            QString binDir = fi.absolutePath();
            QString rootDir = QFileInfo(binDir).absolutePath();
            env.insert("TEXMFROOT", rootDir);
            env.insert("TEXMFCNF", rootDir + "/texmf/web2c:" + rootDir + "/texmf-dist/web2c");
            env.insert("TEXMF", rootDir + "/texmf-dist");
            proc.setProcessEnvironment(env);
        }
    }
#endif

	proc.start(m_program, m_arguments);
	pathSet(pathOrig);
}

bool ExecProgram::execDetached(void) const
{
	bool execResult;

	QString pathOrig = pathExtend();
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
	QProcess proc;
	proc.setProgram(m_program);
	proc.setArguments(m_arguments);
	if (!m_workingDirectory.isEmpty()) {
		proc.setWorkingDirectory(m_workingDirectory);
	}
	setWinProcModifier(proc);
	execResult = proc.startDetached();
#else
	execResult = QProcess::startDetached(m_program, m_arguments, m_workingDirectory);
#endif
	pathSet(pathOrig);
	return execResult;
}

QString ExecProgram::pathExtend(void) const
{
	QChar pathSep = getPathListSeparator();
	QString pathOrig = QString::fromLocal8Bit(qgetenv("PATH"));
	// We add the path from getEnvironmentPath() because it can be extended by shell startup scripts
	QString pathExtended = pathOrig + pathSep + getEnvironmentPath();
	if (!m_additionalSearchPaths.isEmpty()) {
		pathExtended += pathSep + m_additionalSearchPaths;
	}
	pathSet(pathExtended);
	return pathOrig;
}

void ExecProgram::pathSet(const QString &path)
{
	qputenv("PATH", path.toLocal8Bit());
}

void ExecProgram::setWinProcModifier(QProcess &proc) const
{
#ifdef Q_OS_WIN
	if (m_winProcModifier) {
		proc.setCreateProcessArgumentsModifier(m_winProcModifier);
	}
#else
	Q_UNUSED(proc)
#endif
}
