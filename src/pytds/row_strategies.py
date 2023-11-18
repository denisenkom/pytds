import collections
import keyword
import re
from typing import Iterable, Callable, Any, Tuple, NamedTuple, Dict, List


def tuple_row_strategy(column_names: Iterable[str]) -> Callable[[Iterable[Any]], Tuple[Any, ...]]:
    """ Tuple row strategy, rows returned as tuples, default
    """
    return tuple


def list_row_strategy(column_names: Iterable[str]) -> Callable[[Iterable[Any]], List[Any]]:
    """  List row strategy, rows returned as lists
    """
    return list


def dict_row_strategy(column_names: Iterable[str]) -> Callable[[Iterable[Any]], Dict[str, Any]]:
    """ Dict row strategy, rows returned as dictionaries
    """
    # replace empty column names with indices
    column_names = [(name or str(idx)) for idx, name in enumerate(column_names)]

    def row_factory(row: Iterable[Any]) -> Dict[str, Any]:
        return dict(zip(column_names, row))

    return row_factory


def is_valid_identifier(name: str) -> bool:
    """ Returns true if given name can be used as an identifier in Python, otherwise returns false.
    """
    return bool(name and re.match("^[_A-Za-z][_a-zA-Z0-9]*$", name) and not keyword.iskeyword(name))


def namedtuple_row_strategy(column_names: Iterable[str]) -> Callable[[Iterable[Any]], NamedTuple]:
    """ Namedtuple row strategy, rows returned as named tuples

    Column names that are not valid Python identifiers will be replaced
    with col<number>_
    """
    # replace empty column names with placeholders
    clean_column_names = [name if is_valid_identifier(name) else 'col%s_' % idx for idx, name in enumerate(column_names)]
    row_class = collections.namedtuple('Row', clean_column_names)

    def row_factory(row: Iterable[Any]) -> collections.namedtuple:
        return row_class(*row)

    return row_factory


def recordtype_row_strategy(column_names: Iterable[str]) -> Callable[[Iterable[Any]], Any]:
    """ Recordtype row strategy, rows returned as recordtypes

    Column names that are not valid Python identifiers will be replaced
    with col<number>_
    """
    try:
        from namedlist import namedlist as recordtype  # optional dependency
    except ImportError:
        from recordtype import recordtype  # optional dependency
    # replace empty column names with placeholders
    column_names = [name if is_valid_identifier(name) else 'col%s_' % idx for idx, name in enumerate(column_names)]
    recordtype_row_class = recordtype('Row', column_names)

    # custom extension class that supports indexing
    class Row(recordtype_row_class):
        def __getitem__(self, index):
            if isinstance(index, slice):
                return tuple(getattr(self, x) for x in self.__slots__[index])
            return getattr(self, self.__slots__[index])

        def __setitem__(self, index, value):
            setattr(self, self.__slots__[index], value)

    def row_factory(row: Iterable[Any]) -> Row:
        return Row(*row)

    return row_factory
