import numpy

# create array in numpy
a = numpy.array([1,2,3,4,5,6,7,8,9,10])
encoded = numpy.array2string(a, separator=' ')
# load array from string
b = numpy.fromstring(encoded.strip('[]'),dtype=int, sep = ' ')

print(b)
print(encoded)