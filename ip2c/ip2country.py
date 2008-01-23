"""
/*****************************************************************************
//
// IP2Country module
//
// Copyright (C) 2004  L. Petersen, Weird Silence, www.weirdsilence.net
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//
*****************************************************************************/
"""
from struct import unpack, calcsize

class ip2country:
    records = 0
    min = None
    max = None
    recsize = 0
    countries = 0
    countryname = None
    minip = 0
    maxip = 0
    topidx = {}
    _data = ''

    def ip2long( self, ip ):
        b4, b3, b2, b1 = ip.split('.')
        return ( int( b4 ), ( long( b4 ) << 24 ) | ( long( b3 ) << 16 ) | ( long( b2 ) << 8 ) | long( b1 ) )

    def __init__( self ):
        f = file( 'ip2cntry.dat', 'rb' )
        fid = f.read( 4 )
        if fid != 'ip2c':
            return -3
        # Find offset of index
        tmp = f.read( calcsize( '<i' ) )
        idx, = unpack( '<i', tmp )

        # Read index
        f.seek( idx )    
        tmp = f.read( calcsize( '<LLLBH' ) )
        self.records, self.min, self.max, self.recsize, self.countries = unpack( '<LLLBH', tmp )

        # Read country codes
        tmp = f.read( self.countries * 2 )
        # Assemble list of countries
        self.countryname = []
        for i in range( 0, self.countries ):
            self.countryname.append( tmp[ i * 2 : i * 2 + 2 ] )

        # Read min and max A class
        tmp = f.read( calcsize( '<BB' ) )
        self.minip, self.maxip = unpack( '<BB', tmp )
        # Read A class record numbers
        for i in range( self.minip, self.maxip + 1 ):
            tmp = f.read( calcsize( '<l' ) )
            pos, = unpack( '<l', tmp )
            self.topidx[ i ] = pos
        # Now read the data into memory!
        f.seek( 8 )
        self._data = f.read( self.records * self.recsize )
        f.close()

    def countryCode( self, idx ):
        return self.countryname[ idx ]
    
    def lookup( self, ip ):
        orgip = ip
        try:
            aclass,ip = self.ip2long( ip )
        except:
            return -2

        if ip < self.min or ip > self.max or self.topidx[ aclass ] < 0:
            # IP is definitely not in base
            return -1

        # See if it's the first or last IP in the base
        if ip == self.min:
            # Oh the IP was the first ;)
            country, = unpack( '<H', self._data[ 8 : 10 ] )
            return country
        elif ip == self.max:
            # Oh the IP was the last ;)
            pos = ( ( self.records * self.recsize ) - self.recsize + 8 )
            country, = unpack( '<H', self._data[ pos : pos + 2 ] )
            return country

        # Determine where it would be good to start
        if aclass == self.maxip:
            top = self.records
            bottom = abs( self.topidx[ aclass ] ) - 1
        else:
            bottom = abs( self.topidx[ aclass ] ) - 1
            i = 1
            while self.topidx[ aclass + i ] < 0:
                i += 1
            top = self.topidx[ aclass + i ]
        if aclass == self.minip:
            bottom = 0

        found = False
        oldtop = -1
        oldbot = -1
        nextrecord = ( top + bottom ) / 2

        # Divide and conquer
        cnt = 0
        while not found:
            cnt += 1
            pos = ( nextrecord * self.recsize )
            start, = unpack( '<L', self._data[ pos : pos + 4 ] )
            if ip < start:
                # No need for whatever's on top
                top = nextrecord
            else:
                pos += 4
                end, = unpack( '<L', self._data[ pos : pos + 4 ] )
                if ip > end:
                    # No need for whatever's at the bottom
                    bottom = nextrecord
                else:
                    # Yay!
                    pos += 4
                    country, = unpack( '<H', self._data[ pos : pos + 2 ] )
                    return country
            nextrecord = ( top + bottom ) / 2
            if top == oldtop and bottom == oldbot:
                # If this is true, we can't find it
                return -1
            oldtop = top
            oldbot = bottom
        return -1
