import unittest
import sys
import os

class NaturalLanguageTestResult(unittest.TextTestResult):
    def getDescription(self, test):
        name = test._testMethodName
        if name.startswith("test_"):
            name = name[5:]
        name = name.replace("_", " ")
        return f"Testing {name}"

    def addSuccess(self, test):
        unittest.TestResult.addSuccess(self, test)
        if self.showAll:
            self.stream.writeln("passed")
        elif self.dots:
            self.stream.write('.')
            self.stream.flush()

    def addFailure(self, test, err):
        unittest.TestResult.addFailure(self, test, err)
        if self.showAll:
            self.stream.writeln("failed")
        elif self.dots:
            self.stream.write('F')
            self.stream.flush()

    def addError(self, test, err):
        unittest.TestResult.addError(self, test, err)
        if self.showAll:
            self.stream.writeln("error")
        elif self.dots:
            self.stream.write('E')
            self.stream.flush()

    def addSkip(self, test, reason):
        unittest.TestResult.addSkip(self, test, reason)
        if self.showAll:
            self.stream.writeln(f"skipped ({reason})")
        elif self.dots:
            self.stream.write('s')
            self.stream.flush()

class NaturalLanguageTestRunner(unittest.TextTestRunner):
    resultclass = NaturalLanguageTestResult

if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    loader = unittest.TestLoader()
    
    if len(sys.argv) > 1:
        suite = loader.loadTestsFromNames(sys.argv[1:])
    else:
        suite = loader.discover('tests')
        
    runner = NaturalLanguageTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(not result.wasSuccessful())
